#!/usr/bin/env bash
#
# Gate J end to end: the microbenchmarks, the two-target driver with the historical diagnostic,
# and the generated report.
#
# Needs the bench stack (`docker compose -f crates/parse-rust-bench/compose.yaml up -d`), a built
# parse-server at the pin, the instrumented binary, and the released 0.2.0 and 0.2.1 binaries for
# the diagnostic. A missing released binary is reported and skipped, never a failure.
#
# Writes the two record files and the report to $GATE_J_OUT, default target/bench/report. The
# development tree commits its baseline by setting it to its own documents directory. The report is
# generated from the records beside it and is never edited by hand.
#
# Usage:
#   tools/bench/gate-j.sh                       # 30 samples per cell
#   SAMPLES=200 tools/bench/gate-j.sh
#   tools/bench/gate-j.sh --render              # regenerate the report from the committed records
#
set -euo pipefail

cd "$(dirname "$0")/../.."
unset NODE_OPTIONS

OUT="${GATE_J_OUT:-target/bench/report}"
render() {
  python3 tools/bench/report.py "$OUT/0.3.0-e2e.jsonl" "$OUT/0.3.0-micro.jsonl" > "$OUT/0.3.0-baseline.md"
  echo "gate J: report at $OUT/0.3.0-baseline.md"
}
if [[ "${1:-}" == "--render" ]]; then
  render
  exit 0
fi

# Every record names the parse-rust commit it measured. A dirty tree measures code no commit holds,
# so a baseline from one cannot be reproduced. GATE_J_ALLOW_DIRTY=1 runs anyway, as a diagnostic.
if [[ -n "$(git status --porcelain --untracked-files=no)" && "${GATE_J_ALLOW_DIRTY:-}" != 1 ]]; then
  echo "gate J: the tree has uncommitted changes; commit first, or set GATE_J_ALLOW_DIRTY=1 for a diagnostic run" >&2
  exit 1
fi

export PARSE_SERVER_ROOT="${PARSE_SERVER_ROOT:-$(cd .. && pwd)/parse-server-pinned}"

for v in 0.2.0 0.2.1; do
  if [[ ! -x "target/bench/historical/$v/bin/parse-rust" ]]; then
    echo "gate J: no released $v binary; install it with" >&2
    echo "  cargo install parse-rust-cli --version $v --locked --root target/bench/historical/$v" >&2
  fi
done

tools/bench/micro.sh
MICRO=$(ls -t target/bench/micro-*.jsonl | head -1)

CARGO_TARGET_DIR=target/bench-build cargo build --quiet --release -p parse-rust-cli --features bench-instrumentation
cargo build --quiet --release -p parse-rust-bench --bin driver
E2E="target/bench/e2e-gate-$(date -u +%Y%m%dT%H%M%SZ).jsonl"
target/release/driver --samples "${SAMPLES:-30}" --warmup "${WARMUP:-5}" --historical --out "$E2E"

mkdir -p "$OUT"
cp "$E2E" "$OUT/0.3.0-e2e.jsonl"
cp "$MICRO" "$OUT/0.3.0-micro.jsonl"
render
