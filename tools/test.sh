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

# The MongoDB every step uses. Set PARSE_RUST_TEST_MONGO to run the whole suite against another
# server version: `docker run -d -p 127.0.0.1:27917:27017 mongo:9`, then
# `PARSE_RUST_TEST_MONGO=mongodb://127.0.0.1:27917 tools/test.sh`. The Rust integration tests, the
# conformance harness and the schema-format oracle read the same variable.
export PARSE_RUST_TEST_MONGO="${PARSE_RUST_TEST_MONGO:-mongodb://127.0.0.1:27017}"
TEST_MONGO="$PARSE_RUST_TEST_MONGO"
export CONFORMANCE_MONGO="${CONFORMANCE_MONGO:-$TEST_MONGO}"

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

# A step that cannot be trusted, as distinct from one that was not run. A skip is a statement that
# nothing was measured; this is a statement that something was measured against the wrong thing,
# which is the more dangerous of the two and must not render the same way.
fail_step() {
  printf '[FAIL] %-34s      %s\n' "$1" "$2"
  FAILED=1
  STEPS+=("$1")
}

have() { command -v "$1" >/dev/null 2>&1; }

# **The oracle has to be at the pin, and until this check it was not.**
#
# `../parse-server` is the owner's working repository. It moves, and it was three commits past the
# pin while every gate below reported green: the differentials were measuring parse-rust against
# whatever happened to be checked out, and calling the result compatibility with the declared
# release target. That is the same class of defect as a gate configured around a gap, and it is
# worse, because it silently invalidates every measurement rather than one.
#
# The citation check reads content at the pin through `git show`, so it was never affected. The
# runtime gates load `lib/`, which is whatever the checkout built.
#
# A checkout that is not at the pin, and no pinned worktree to fall back on, is a real problem
# that wants a human: `oracle_problem` below stops every step that needs the oracle and names both
# revisions.

# The declared release target. Every differential below is only as good as this.
PIN_COMMIT=$(awk '/^parse-server /{print $3}' PIN)

# Where the oracle lives.
#
# **The default checkout moves, so it is used only when it happens to be at the pin.** It is the
# owner's working repository for authoring upstream pull requests, and it was three commits ahead
# while every gate reported green. A pinned worktree beside it is preferred automatically when the
# working checkout has drifted, so the correct behaviour is the default rather than something a
# reader has to know to ask for:
#
#     git -C ../parse-server worktree add ../parse-server-pinned <pin>
#     cd ../parse-server-pinned && npm ci && npm run build
#
# `PARSE_SERVER_ROOT` still overrides both, and is resolved against this repository.
PS_ROOT="${PARSE_SERVER_ROOT:-../parse-server}"
PINNED_WORKTREE="../parse-server-pinned"
if [[ -z "${PARSE_SERVER_ROOT:-}" ]] \
   && [[ "$(git -C "$PS_ROOT" rev-parse HEAD 2>/dev/null)" != "$PIN_COMMIT" ]] \
   && [[ "$(git -C "$PINNED_WORKTREE" rev-parse HEAD 2>/dev/null)" == "$PIN_COMMIT" ]] \
   && [[ -f "$PINNED_WORKTREE/lib/index.js" ]]; then
  PS_ROOT="$PINNED_WORKTREE"
  export PARSE_SERVER_ROOT="$PS_ROOT"
  echo "oracle: $PS_ROOT (the working checkout is not at the pin)"
fi

# Why the oracle can be trusted, or the reason it cannot.
#
# **Four conditions, and the first one used to be a hole.** The original check ended
# `|| return 0`, so a `PARSE_SERVER_ROOT` pointing at anything that is not a git checkout passed
# verification: an npm-installed parse-server of any version satisfied it. A guard that answers
# "fine" when it cannot tell is worse than no guard, and this one was written to close exactly that
# class of problem.
#
# The last condition is the one that matters most and is easiest to overlook: the gates do not load
# `src/`, they load `lib/`, which is compiled output and is gitignored. `HEAD` can sit exactly on
# the pin while `lib/` was built from something else entirely. A clean tree at the pin means `src/`
# *is* the pin's source, and `lib/` being newer than every tracked source file means it was built
# after that source was in place. That is not a cryptographic guarantee, but it rules out the
# realistic failure: editing upstream, rebuilding, and forgetting.
oracle_problem() {
  local head dirty stale
  if ! git -C "$PS_ROOT" rev-parse --git-dir >/dev/null 2>&1; then
    printf '%s is not a git checkout, so its revision cannot be verified' "$PS_ROOT"
    return 0
  fi
  head=$(git -C "$PS_ROOT" rev-parse HEAD 2>/dev/null)
  if [[ "$head" != "$PIN_COMMIT" ]]; then
    printf 'checkout is at %s, not the pin %s' "${head:0:8}" "${PIN_COMMIT:0:12}"
    return 0
  fi
  dirty=$(git -C "$PS_ROOT" status --porcelain --untracked-files=no 2>/dev/null | head -3)
  if [[ -n "$dirty" ]]; then
    printf 'checkout is at the pin but has local modifications, so `lib/` may not be the pin'
    return 0
  fi
  if [[ ! -f "$PS_ROOT/lib/index.js" ]]; then
    printf '%s/lib is not built, and the gates load lib rather than src' "$PS_ROOT"
    return 0
  fi
  stale=$(find "$PS_ROOT/src" -type f -newer "$PS_ROOT/lib/index.js" -print -quit 2>/dev/null)
  if [[ -n "$stale" ]]; then
    printf 'lib/ is older than src/, so the compiled oracle is not this source'
    return 0
  fi
  return 1
}

# **A timestamp is not a build, and the difference is the last hole in this check.**
#
# The conditions above establish that `src/` is the pin and that `lib/` is newer than it. They
# cannot establish that `lib/` is *that* source compiled: a hand-edited `lib/RestQuery.js`, a build
# that failed halfway, or one affected by an input outside `src/` all satisfy them. The gates load
# `lib/`, so those are exactly the cases that matter.
#
# Rebuilding is the only check that answers the question, so `PARSE_ORACLE_REBUILD=1` does it. It is
# opt-in rather than automatic because it costs a minute and the ordinary case is a worktree nobody
# touches; CI, and anyone who wants the guarantee rather than the heuristic, sets it.
rebuild_oracle_if_asked() {
  [[ "${PARSE_ORACLE_REBUILD:-0}" == "1" ]] || return 0
  echo "rebuilding $PS_ROOT/lib from source (PARSE_ORACLE_REBUILD=1)"
  if ! (cd "$PS_ROOT" && npm run build >/dev/null 2>&1); then
    echo "[FAIL] could not rebuild $PS_ROOT/lib; the gates below would load an unverified artifact"
    FAILED=1
    return 1
  fi
}

oracle_revision_ok() { ! oracle_problem >/dev/null; }
oracle_mismatch_reason() { oracle_problem; }


rebuild_oracle_if_asked

echo "parse-rust test harness"
echo "started $(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo

# --- always available ------------------------------------------------------
run "cargo fmt --check"        cargo fmt --all -- --check
run "cargo clippy"             cargo clippy --workspace --all-targets -- -D warnings
run "cargo test (unit)"        cargo test --workspace

# --- needs the upstream checkout at the pin --------------------------------
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
elif ! oracle_revision_ok; then
  # The bcrypt and `MongoTransform` differentials shell out to the same checkout the gates boot, so
  # they answer to the same revision and are trustworthy on the same condition.
  fail_step "differentials and integration" "$(oracle_mismatch_reason)"
else
  # `--ignored` covers every such test in the workspace: the number formatter and bcrypt
  # differentials, the `_SCHEMA` format oracle, the MongoTransform oracle, and the Mongo adapter
  # integration tests. Several need the MongoDB at $TEST_MONGO. They fail loudly rather than skipping,
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
# Any trailing `NAME=VALUE` arguments are added to the server's environment, which is how the
# option-sensitive gates get a second server configured differently without a second helper.
with_server() {
  local runner="$1"; shift
  local extra_env=("$@")
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
  local uri="${TEST_MONGO}/${db}"
  local log; log=$(mktemp -t parse-rust-harness)
  # `allowClientClassCreation` on, matching the `allowClientClassCreation: true` every gate script
  # already passes to the parse-server it boots. Both servers have to agree, or a differential run
  # measures the option instead of the behavior under test. The shipped default is `false`, as it
  # is upstream, and it is asserted in `parse-rust-rest`'s pipeline tests rather than here: no gate
  # exercises the default, which is worth knowing when reading a green log.
  env "${extra_env[@]+"${extra_env[@]}"}" \
    PARSE_SERVER_APPLICATION_ID=test PARSE_SERVER_MASTER_KEY=test \
    PARSE_SERVER_ALLOW_CLIENT_CLASS_CREATION=true \
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

run_features() { node tools/spec/features.spec.mjs "$1"; }
run_gate_a() { node tools/spec/poc-flow.mjs "$1" test - test "$2"; }
run_gate_b() { node tools/spec/data-fidelity.mjs "$1" "$2"; }
# Gate C runs against parse-rust either way. `--upstream` additionally boots parse-server on its
# own database and replays every assertion there, which is the half that makes it differential.
#
# It runs twice, because `enableSanitizedErrorResponse` puts two different sets of messages on the
# wire and both are contract. The first pass is both servers at the upstream default, which is the
# configuration a real deployment has; the second is both with the option off, which is the only
# way the detailed strings get differentially checked at all.
run_gate_c_both() { node tools/spec/authorization.mjs "$1" test test "--upstream=$2"; }
run_gate_c_rust() { node tools/spec/authorization.mjs "$1" test test; }
run_gate_c_both_detailed() { node tools/spec/authorization.mjs "$1" test test "--upstream=$2" --detailed; }
run_gate_c_rust_detailed() { node tools/spec/authorization.mjs "$1" test test --detailed; }
run_gate_d() { node tools/spec/shared-auth-state.mjs "$1" "$2"; }

# Gate F of 0.3.0: upstream's own spec files against parse-rust, the dead-server control and the
# pinned parse-server. Builds the harness binary into its own target directory, because the
# `test-harness` feature must never reach the `target/debug/parse-rust` the other gates use.
run_gate_f() {
  CARGO_TARGET_DIR=target/harness cargo build -p parse-rust-cli --features test-harness --quiet || return 1
  PARSE_SERVER_ROOT="$PS_ROOT" node tools/conformance/run.mjs
}

# Gate H: the control plane's acceptance files, against both servers through the same supervisor.
# Reuses Gate F's harness binary, so it runs after it.
run_gate_h() {
  CARGO_TARGET_DIR=target/harness cargo build -p parse-rust-cli --features test-harness --quiet || return 1
  PARSE_SERVER_ROOT="$PS_ROOT" node tools/conformance/run.mjs --control-plane
}

# Gate E is the one gate `with_server` cannot host. It varies server configuration across four
# servers and it needs a second source address, so it boots its own and takes only a database.
# Gate I runs in the same script for the same reason.
run_gate_e() {
  cargo build --workspace --quiet || return 1
  if [[ ! -x ./target/debug/parse-rust ]]; then
    echo "./target/debug/parse-rust is missing; the binary name and this script disagree"
    return 1
  fi
  node tools/spec/stock-config.mjs "${TEST_MONGO}/parse_rust_e_$$_${RANDOM}"
}

# Every runner resolves the `parse` npm SDK from the upstream checkout, and gates B, C and D boot a
# real parse-server out of it. The two are separate conditions: CI installs the SDK without the
# checkout, so the SDK can be present while `lib/index.js` is not.
have_sdk() { [[ -d "$PS_ROOT/node_modules/parse" ]]; }
have_upstream_server() { [[ -f "$PS_ROOT/lib/index.js" ]]; }


if [[ $QUICK -eq 1 ]]; then
  skip "conformance: features.spec" "--quick"
  skip "gate A: SDK flow" "--quick"
  skip "gate B: data fidelity" "--quick"
  skip "gate C: authorization" "--quick"
  skip "gate C: detailed messages" "--quick"
  skip "gate D: shared auth state" "--quick"
  skip "gates E and I: stock configuration" "--quick"
  skip "gate F: upstream spec suite" "--quick"
  skip "gate H: reconfigure control plane" "--quick"
elif ! oracle_revision_ok; then
  # A hard failure, not a skip. A skip says "not measured here"; this says "measured against the
  # wrong thing", and the two must not read the same.
  for step in "conformance: features.spec" "gate A: SDK flow" "gate B: data fidelity" \
              "gate C: authorization" "gate C: detailed messages" "gate D: shared auth state" \
              "gates E and I: stock configuration" "gate F: upstream spec suite" \
              "gate H: reconfigure control plane"; do
    fail_step "$step" "$(oracle_mismatch_reason)"
  done
  echo "       to fix: git -C $PS_ROOT checkout $PIN_COMMIT"
  echo "       or:     build ../parse-server-pinned and set PARSE_SERVER_ROOT to it"
elif ! have node || ! have curl; then
  skip "conformance: features.spec" "node or curl not on PATH"
  skip "gate A: SDK flow" "node or curl not on PATH"
  skip "gate B: data fidelity" "node or curl not on PATH"
  skip "gate C: authorization" "node or curl not on PATH"
  skip "gate C: detailed messages" "node or curl not on PATH"
  skip "gate D: shared auth state" "node or curl not on PATH"
  skip "gates E and I: stock configuration" "node or curl not on PATH"
  skip "gate F: upstream spec suite" "node or curl not on PATH"
  skip "gate H: reconfigure control plane" "node or curl not on PATH"
elif ! have_sdk; then
  skip "conformance: features.spec" "no parse SDK under $PS_ROOT/node_modules"
  skip "gate A: SDK flow" "no parse SDK under $PS_ROOT/node_modules"
  skip "gate B: data fidelity" "no parse SDK under $PS_ROOT/node_modules"
  skip "gate C: authorization" "no parse SDK under $PS_ROOT/node_modules"
  skip "gate C: detailed messages" "no parse SDK under $PS_ROOT/node_modules"
  skip "gate D: shared auth state" "no parse SDK under $PS_ROOT/node_modules"
  skip "gates E and I: stock configuration" "no parse SDK under $PS_ROOT/node_modules"
  skip "gate F: upstream spec suite" "no parse SDK under $PS_ROOT/node_modules"
  skip "gate H: reconfigure control plane" "no parse SDK under $PS_ROOT/node_modules"
else
  run "conformance: features.spec"  with_server run_features
  # The acceptance gates. Their assertions hold against real parse-server too, except the few in
  # Gate I that state each server's answer where parse-rust deliberately differs, so a failure
  # means parse-rust diverged rather than that the expectation was invented.
  run "gate A: SDK flow"            with_server run_gate_a
  # The second parse-rust is booted with `enableSanitizedErrorResponse` off, which is the only
  # way to exercise the detailed messages. The gate matches the upstream half to it.
  SANITIZE_OFF=PARSE_SERVER_ENABLE_SANITIZED_ERROR_RESPONSE=false
  if have_upstream_server; then
    run "gate B: data fidelity"     with_server run_gate_b
    run "gate C: authorization"     with_server run_gate_c_both
    run "gate C: detailed messages" with_server run_gate_c_both_detailed "$SANITIZE_OFF"
    run "gate D: shared auth state" with_server run_gate_d
    run "gates E and I: stock configuration" run_gate_e
    run "gate F: upstream spec suite"  run_gate_f
    run "gate H: reconfigure control plane" run_gate_h
  else
    # Named where they would have run rather than dropped, so a short green log cannot be mistaken
    # for a full one. Gates B and D boot parse-server themselves and have no half that runs
    # without it; gate C does, and running only that half is worth saying out loud.
    skip "gate B: data fidelity"    "no parse-server at $PS_ROOT; the gate boots one"
    run  "gate C: authorization"    with_server run_gate_c_rust
    run  "gate C: detailed messages" with_server run_gate_c_rust_detailed "$SANITIZE_OFF"
    skip "gate C: upstream half"    "no parse-server at $PS_ROOT; parse-rust half ran above"
    skip "gate D: shared auth state" "no parse-server at $PS_ROOT; the gate boots one"
    skip "gates E and I: stock configuration" "no parse-server at $PS_ROOT; the gate boots one"
    skip "gate F: upstream spec suite" "no parse-server at $PS_ROOT; its oracle run needs it"
    skip "gate H: reconfigure control plane" "no parse-server at $PS_ROOT; the supervisor is checked against it"
  fi
fi

echo
if [[ $FAILED -eq 0 ]]; then
  echo "finished $(date -u +%Y-%m-%dT%H:%M:%SZ), $(( $(date +%s) - STARTED ))s, ${#STEPS[@]} steps, all passed"
else
  echo "finished $(date -u +%Y-%m-%dT%H:%M:%SZ), $(( $(date +%s) - STARTED ))s, FAILURES ABOVE"
fi
exit $FAILED
