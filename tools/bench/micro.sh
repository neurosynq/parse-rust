#!/usr/bin/env bash
#
# Gate J's microbenchmark half: every comparable family on every frozen corpus, both targets,
# with the corpus hash in every record.
#
# Builds the Rust harness in release, checks the committed corpora still regenerate byte for
# byte, runs the Rust side and then the Node side into one JSONL file under target/bench/, and
# verifies the file is complete: for each family and each corpus, exactly one rust record and one
# node record, each carrying the hash of the corpus file on disk. A missing or duplicated cell
# fails with the cell named.
#
# The closing table is raw p50s labelled baseline-unclassified. It carries no ratios and no
# verdicts, because none are justified before 0.4.0's A/A noise floor exists.
#
# Usage:
#   tools/bench/micro.sh
#   PARSE_SERVER_ROOT=/path/to/built/parse-server tools/bench/micro.sh
#
set -euo pipefail

cd "$(dirname "$0")/../.."
ROOT=$(pwd)

# An editor's auto-attach NODE_OPTIONS makes node wait on a debugger, and a debugger attached
# during a timed loop is a measurement of the debugger. See tools/test.sh.
unset NODE_OPTIONS

UPSTREAM=$(cd "$ROOT" && cd "${PARSE_SERVER_ROOT:-../parse-server-pinned}" 2>/dev/null && pwd) || {
  echo "micro.sh: upstream checkout not found at ${PARSE_SERVER_ROOT:-../parse-server-pinned}" >&2
  echo "  build one: git -C ../parse-server worktree add ../parse-server-pinned <pin> && npm ci && npm run build" >&2
  exit 1
}
if [[ ! -f "$UPSTREAM/lib/Adapters/Storage/Mongo/MongoTransform.js" ]]; then
  echo "micro.sh: $UPSTREAM has no built lib/; run npm run build there" >&2
  exit 1
fi

# The Node numbers are parse-server's only if they come from the pinned revision. A checkout that
# has drifted measures an undeclared revision and calls it the release target.
PIN_SHA=$(awk '/^parse-server /{print $3}' PIN)
UPSTREAM_SHA=$(git -C "$UPSTREAM" rev-parse HEAD)
if [[ "$UPSTREAM_SHA" != "$PIN_SHA" ]]; then
  echo "micro.sh: $UPSTREAM is at $UPSTREAM_SHA, the pin is $PIN_SHA" >&2
  exit 1
fi
if [[ -n "$(git -C "$UPSTREAM" status --porcelain --untracked-files=no)" ]]; then
  echo "micro.sh: $UPSTREAM has modified tracked files; its lib/ is not the pin's" >&2
  exit 1
fi
# `lib/` is ignored by git, so a clean tree at the pin says nothing about what was built, and a
# build newer than the sources says nothing about which sources. This recompiles `src/` in memory
# and compares it to `lib/`; its header states what it still trusts.
node tools/bench/verify-upstream-build.cjs "$UPSTREAM" >/dev/null || exit 1

cargo build --quiet --release -p parse-rust-bench --bin micro --bin make-corpus
target/release/make-corpus --check >/dev/null || {
  echo "micro.sh: committed corpora differ from the generator; regenerating resets every baseline" >&2
  exit 1
}

mkdir -p target/bench
OUT="target/bench/micro-$(date -u +%Y%m%dT%H%M%SZ).jsonl"
: > "$OUT"

target/release/micro --out "$OUT"
PARSE_SERVER_ROOT="$UPSTREAM" node crates/parse-rust-bench/js-micro/micro.mjs --out "$OUT"

python3 - "$OUT" <<'PY'
import hashlib, json, sys
from pathlib import Path

out = Path(sys.argv[1])
corpus_dir = Path("crates/parse-rust-bench/corpus")
matrix = json.loads(Path("crates/parse-rust-bench/matrix.json").read_text())
families = matrix["families"]
corpora = [f"{s}-{h}" for s in matrix["sizes"] for h in matrix["shapes"]]
targets = ["rust", "node"]

hashes = {}
for name in corpora:
    path = corpus_dir / f"{name}.json"
    if not path.exists():
        sys.exit(f"micro.sh: corpus {path} is missing")
    hashes[name] = hashlib.sha256(path.read_bytes()).hexdigest()[:16]

cells = {}
problems = []
for n, line in enumerate(out.read_text().splitlines(), 1):
    r = json.loads(line)
    for required in ["db_share_p50", "transport", "corpus", "latency_us"]:
        if required not in r:
            problems.append(f"line {n}: record has no `{required}`")
    if r.get("verdict") != "baseline-unclassified":
        problems.append(f"line {n}: verdict is {r.get('verdict')!r}")
    key = (r.get("family"), r.get("corpus", {}).get("name"), r.get("target"))
    cells.setdefault(key, []).append(r)

for family in families:
    for name in corpora:
        for target in targets:
            records = cells.get((family, name, target), [])
            cell = f"{target} {family} {name}"
            if len(records) != 1:
                problems.append(f"{cell}: {len(records)} records, expected exactly one")
                continue
            got = records[0]["corpus"].get("hash")
            if got != hashes[name]:
                problems.append(f"{cell}: corpus hash {got}, file on disk is {hashes[name]}")

expected = {(f, c, t) for f in families for c in corpora for t in targets}
for key in cells:
    if key not in expected:
        problems.append(f"unexpected cell {key}")

if problems:
    print("micro.sh: incomplete run", file=sys.stderr)
    for p in problems:
        print(f"  {p}", file=sys.stderr)
    sys.exit(1)

print()
print("p50 per operation, microseconds. baseline-unclassified: no verdicts before the A/A noise floor.")
print(f"{'corpus':<14} {'family':<14} {'rust':>10} {'node':>10}")
for name in corpora:
    for family in families:
        rust = cells[(family, name, "rust")][0]["latency_us"]["p50"]
        node = cells[(family, name, "node")][0]["latency_us"]["p50"]
        print(f"{name:<14} {family:<14} {rust:>10.3f} {node:>10.3f}")
print()
print(f"complete: every family on every corpus, both targets. {out}")
PY
