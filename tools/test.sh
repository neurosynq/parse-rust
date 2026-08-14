#!/usr/bin/env bash
#
# The test harness entry point. This is what CI runs and what you should run before committing.
#
# Output discipline: a header, one line per step written and flushed as it completes, and a footer
# only on completion. That means "is it done?" is answerable from the log alone rather than from
# process state, which matters once the conformance suite makes this a long run. Never pipe a long
# run through a buffering filter; tee to a file so the log fills line by line.
#
# Usage:
#   tools/test.sh            # everything available on this machine
#   tools/test.sh --quick    # skip anything needing node or the upstream checkout
#
set -uo pipefail

cd "$(dirname "$0")/.."

# Editors inject `NODE_OPTIONS=--require .../bootloader.js` for auto-attach debugging. Every node
# process then waits for a debug server, so a harness that inherits it hangs instead of running,
# and the failure looks like a slow test rather than an environment leak. The harness controls its
# own environment.
unset NODE_OPTIONS

QUICK=0
[[ "${1:-}" == "--quick" ]] && QUICK=1

STEPS=()
FAILED=0
STARTED=$(date +%s)

run() {
  local name="$1"; shift
  local start; start=$(date +%s)
  local out; local status
  out=$("$@" 2>&1); status=$?
  local secs=$(( $(date +%s) - start ))
  if [[ $status -eq 0 ]]; then
    printf '[ ok ] %-34s %3ds\n' "$name" "$secs"
  else
    printf '[FAIL] %-34s %3ds\n' "$name" "$secs"
    printf '%s\n' "$out" | sed 's/^/       | /'
    FAILED=1
  fi
  STEPS+=("$name")
}

skip() {
  printf '[skip] %-34s      %s\n' "$1" "$2"
}

have() { command -v "$1" >/dev/null 2>&1; }

echo "parse-rust test harness"
echo "started $(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo

# --- always available ------------------------------------------------------
run "cargo fmt --check"        cargo fmt --all -- --check
run "cargo clippy"             cargo clippy --workspace --all-targets -- -D warnings
run "cargo test (unit)"        cargo test --workspace

# --- needs the upstream checkout at the pin --------------------------------
PIN_COMMIT=$(awk '/^parse-server /{print $3}' PIN)
if [[ $QUICK -eq 1 ]]; then
  skip "citations resolve at pin" "--quick"
elif [[ ! -d ../parse-server/.git ]]; then
  skip "citations resolve at pin" "../parse-server not present"
elif ! git -C ../parse-server cat-file -e "${PIN_COMMIT}^{commit}" 2>/dev/null; then
  skip "citations resolve at pin" "pin ${PIN_COMMIT} not in ../parse-server"
else
  run "citations resolve at pin"  python3 tools/check-citations.py
fi

# --- needs node ------------------------------------------------------------
# The differential is #[ignore]d in cargo so that a machine without node still gets a green
# unit suite. It is not optional here: it is the only thing that proves the number formatter
# against the actual oracle rather than against expectations someone typed in.
if [[ $QUICK -eq 1 ]]; then
  skip "differentials and integration" "--quick"
elif ! have node; then
  skip "differentials and integration" "node not on PATH"
else
  # `--ignored` covers every such test in the workspace: the number formatter and bcrypt
  # differentials, the `_SCHEMA` format oracle, the MongoTransform oracle, and the Mongo adapter
  # integration tests. Several need a MongoDB on 27017. They fail loudly rather than skipping,
  # because a differential that quietly does not run is worse than not having one.
  run "differentials and integration"  cargo test --workspace -- --ignored
fi

# --- conformance: boot parse-rust and replay a spec file's assertions -------
# Every assertion in these runners holds against real parse-server too, so a failure here means
# parse-rust diverged rather than that the expectation was invented. That property is what makes
# the runners worth anything, and it is why parse-rust-specific checks do not live in them: the
# `/serverInfo` capability values, which deliberately differ from upstream, are asserted in
# `crates/parse-rust-server/tests/server_info.rs` instead.
# Boot parse-rust on an ephemeral port into a per-run database, run `$1` with the base URL and
# the mongo URI, then tear down. No fixed port and no fixed database, so parallel batteries cannot
# collide with each other or with a real parse-server.
with_server() {
  local runner="$1"
  cargo build --workspace --quiet || return 1

  # Fail loudly on a missing binary. Without this the launch backgrounds a nonexistent path, the
  # readiness loop below spins for eight seconds, and the run reports "server never reported a
  # bound address", which reads as a server bug rather than a build that did not produce the
  # executable this script expects.
  if [[ ! -x ./target/debug/parse-rust ]]; then
    echo "./target/debug/parse-rust is missing; the binary name and this script disagree"
    return 1
  fi

  local db="parse_rust_h_$$_${RANDOM}"
  local uri="mongodb://127.0.0.1:27017/${db}"
  local log; log=$(mktemp -t parse-rust-harness)
  PARSE_SERVER_APPLICATION_ID=test PARSE_SERVER_MASTER_KEY=test \
    PARSE_SERVER_MOUNT_PATH=/parse PORT=0 PARSE_SERVER_DATABASE_URI="$uri" \
    ./target/debug/parse-rust >"$log" 2>&1 &
  local pid=$!

  local base=""
  for _ in $(seq 1 80); do
    base=$(sed -n 's|^parse-rust listening on \(http://[^ ]*\)$|\1|p' "$log" 2>/dev/null | head -1)
    [[ -n "$base" ]] && break
    sleep 0.1
  done

  local status=1
  if [[ -z "$base" ]]; then
    echo "server never reported a bound address"; cat "$log"
  else
    for _ in $(seq 1 80); do
      curl -fsS "$base/parse/health" >/dev/null 2>&1 && break
      sleep 0.1
    done
    "$runner" "$base/parse" "$uri"
    status=$?
  fi

  kill $pid 2>/dev/null; wait $pid 2>/dev/null; rm -f "$log"
  return $status
}

run_gate_a() { node tools/spec/poc-flow.mjs "$1" test - test "$2"; }
run_gate_b() { node tools/spec/data-fidelity.mjs "$1" "$2"; }
run_features() { node tools/spec/features.spec.mjs "$1"; }

if [[ $QUICK -eq 1 ]]; then
  skip "conformance: features.spec" "--quick"
  skip "gate A: SDK flow" "--quick"
  skip "gate B: data fidelity" "--quick"
elif ! have node || ! have curl; then
  skip "conformance: features.spec" "node or curl not on PATH"
  skip "gate A: SDK flow" "node or curl not on PATH"
  skip "gate B: data fidelity" "node or curl not on PATH"
else
  run "conformance: features.spec"  with_server run_features
  # The two 0.1.0 acceptance gates. Both have also been verified against real parse-server, so a
  # failure means parse-rust diverged rather than that the expectation was invented.
  run "gate A: SDK flow"           with_server run_gate_a
  run "gate B: data fidelity"      with_server run_gate_b
fi

echo
if [[ $FAILED -eq 0 ]]; then
  echo "finished $(date -u +%Y-%m-%dT%H:%M:%SZ), $(( $(date +%s) - STARTED ))s, ${#STEPS[@]} steps, all passed"
else
  echo "finished $(date -u +%Y-%m-%dT%H:%M:%SZ), $(( $(date +%s) - STARTED ))s, FAILURES ABOVE"
fi
exit $FAILED
