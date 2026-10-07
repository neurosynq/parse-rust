#!/usr/bin/env python3
"""Render a benchmark run's JSONL records into a markdown report.

    tools/bench/report.py E2E.jsonl MICRO.jsonl > report.md

Generated, never hand-edited: rerunning over the same inputs produces the same file. The report
carries raw distributions only. Every record is checked for the `baseline-unclassified` verdict
and the report refuses to render one that claims anything else, because no verdict is justified
before 0.4.0's A/A noise floor exists.
"""

import hashlib
import json
import sys
from pathlib import Path

BENCH = Path(__file__).resolve().parent.parent.parent / "crates" / "parse-rust-bench"
# The completeness matrix comes from one file, never from the records: a report that inferred its
# rows from what it was given would render a run missing a whole family as finished.
MATRIX = json.loads((BENCH / "matrix.json").read_text(encoding="utf-8"))
WORKLOADS = MATRIX["workloads"]
TARGETS = MATRIX["targets"]
RUNGS = MATRIX["rungs"]
CALIBRATED = MATRIX["calibrated"]
FAMILIES = MATRIX["families"]
CORPORA = [f"{size}-{shape}" for size in MATRIX["sizes"] for shape in MATRIX["shapes"]]


def load(path):
    with open(path, encoding="utf-8") as f:
        return [json.loads(line) for line in f if line.strip()]


def fail(message):
    print(f"report.py: {message}", file=sys.stderr)
    sys.exit(1)


def us(value):
    return f"{value:,.1f}"


def main():
    if len(sys.argv) != 3:
        fail("usage: report.py E2E.jsonl MICRO.jsonl")
    e2e, micro = load(sys.argv[1]), load(sys.argv[2])
    for r in e2e + micro:
        if r.get("verdict") != "baseline-unclassified":
            fail(f"record carries verdict {r.get('verdict')!r}; this report publishes none")

    for r in e2e + micro:
        if "transport" not in r:
            fail(f"a {r.get('kind')} record has no transport")
        if "db_share_p50" not in r or r["db_share_p50"] is None:
            fail(f"a {r.get('kind')} record has no db_share")
    runs = {r.get("run_id") for r in e2e}
    if len(runs) != 1:
        fail(f"{sys.argv[1]} holds {len(runs)} runs; render one run at a time")

    measured = [r for r in e2e if r["kind"] == "e2e"]
    historical = [r for r in e2e if r["kind"] == "historical"]
    if not measured:
        fail(f"{sys.argv[1]} has no e2e records")
    if not micro:
        fail(f"{sys.argv[2]} has no records")
    # The same completeness and calibration the driver and micro.sh enforce, against the fixed
    # matrix, so a records file either would have failed cannot be rendered into a report that
    # looks finished.
    for target in TARGETS:
        for workload in WORKLOADS:
            for rung in RUNGS:
                found = [r for r in measured if r["target"] == target and r["workload"] == workload
                         and r["db_latency_rung_ms"] == rung]
                if len(found) != 1:
                    fail(f"{len(found)} records for {target} {workload} at {rung} ms; expected exactly one")
                if not isinstance(found[0]["db_share_p50"], (int, float)):
                    fail(f"{target} {workload} at {rung} ms has no measured db_share")
        cal = sorted(r["workload"] for r in e2e if r["kind"] == "calibration" and r["target"] == target)
        if cal != sorted(CALIBRATED):
            fail(f"{target}: calibration covers {cal}, expected {sorted(CALIBRATED)}")
        if not all(r["passed"] is True for r in e2e if r["kind"] == "calibration" and r["target"] == target):
            fail(f"{target}: calibration failed")
    for r in measured:
        key = (r["target"], r["workload"], r["db_latency_rung_ms"])
        if r["target"] not in TARGETS or r["workload"] not in WORKLOADS or r["db_latency_rung_ms"] not in RUNGS:
            fail(f"e2e record {key} is outside the matrix")

    hashes = {}
    for name in CORPORA:
        path = BENCH / "corpus" / f"{name}.json"
        if not path.exists():
            fail(f"corpus {path} is missing")
        hashes[name] = hashlib.sha256(path.read_bytes()).hexdigest()[:16]
    mcells = {}
    for r in micro:
        key = (r.get("target"), r.get("family"), r.get("corpus", {}).get("name"))
        if key[0] not in TARGETS or key[1] not in FAMILIES or key[2] not in CORPORA:
            fail(f"micro record {key} is outside the matrix")
        mcells.setdefault(key, []).append(r)
    for family in FAMILIES:
        for corpus in CORPORA:
            for target in TARGETS:
                found = mcells.get((target, family, corpus), [])
                if len(found) != 1:
                    fail(f"{len(found)} micro records for {target} {family} {corpus}; expected exactly one")
                if found[0]["corpus"].get("hash") != hashes[corpus]:
                    fail(f"micro {target} {family} {corpus} ran on corpus {found[0]['corpus'].get('hash')}, "
                         f"the file on disk is {hashes[corpus]}")

    ctx = measured[0]["context"]
    rungs = RUNGS
    calibration = [r for r in e2e if r["kind"] == "calibration"]
    cell = {(r["target"], r["workload"], r["db_latency_rung_ms"]): r for r in measured + historical}

    out = []
    w = out.append
    w("# Benchmark baseline, 0.3.0")
    w("")
    w("Generated by `tools/bench/report.py` from the JSONL records beside this file. Do not edit by")
    w("hand; rerun `tools/bench/gate-j.sh` instead.")
    w("")
    w("**Every number here is `baseline-unclassified`.** No `faster`, `slower` or `equivalent`")
    w("verdict is published at 0.3.0, because the A/A noise floor that would justify one is 0.4.0")
    w("work. A difference between two columns below is an observation, not a claim.")
    w("")
    w("## Context")
    w("")
    w(f"- run: `{measured[0]['run_id']}`")
    w(f"- parse-rust: `{ctx['parse_rust_sha'][:12]}`" + (" (dirty tree)" if ctx["parse_rust_dirty"] else ""))
    w(f"- parse-server: `{ctx['upstream']['sha'][:12]}`, clean: {str(ctx['upstream']['clean']).lower()}")
    w(f"- node `{ctx['node']}`, `{ctx['rustc']}`")
    w(f"- {ctx['cpu']}, {ctx['os']}")
    p = measured[0]["params"]
    w(f"- concurrency {p['concurrency']}, {p['samples']} samples after {p['warmup']} warmup per cell")
    w("- database latency is injected per command by toxiproxy between each server and MongoDB")
    w("")
    w("## End to end")
    w("")
    w("Latency is wall clock per request in microseconds. Database time is the union of command")
    w("intervals attributed to the request, measured inside each server by command monitoring.")
    w("The 10 ms rung is the calibration point: on workloads whose commands run one after another,")
    w("database time must be the command count times 10 ms within tolerance, or the run fails.")
    for rung in rungs:
        w("")
        w(f"### {rung} ms per database command")
        w("")
        w("| workload | target | p50 | p99 | db p50 | db ops | db share |")
        w("|---|---|---:|---:|---:|---:|---:|")
        for workload in WORKLOADS:
            for target in ["node", "rust"]:
                r = cell.get((target, workload, rung))
                if r is None:
                    fail(f"missing cell {target} {workload} {rung} ms")
                lat = r["latency_us"]
                w(
                    f"| `{workload}` | {target} | {us(lat['p50'])} | {us(lat['p99'])} "
                    f"| {us(r['db_micros_p50'])} | {r['db_ops_p50']} | {r['db_share_p50']:.3f} |"
                )
    if calibration:
        w("")
        w("### Calibration at 10 ms")
        w("")
        w("| target | workload | db p50 | db ops | expected | passed |")
        w("|---|---|---:|---:|---:|---|")
        for r in calibration:
            w(
                f"| {r['target']} | `{r['workload']}` | {us(r['db_micros_p50'])} "
                f"| {r['db_ops_p50']:g} | {us(r['expected_micros'])} | {str(r['passed']).lower()} |"
            )
    if historical:
        w("")
        w("## Historical diagnostic")
        w("")
        w("The published 0.2.0 and 0.2.1 binaries, run on the same machine and workloads. Wall clock")
        w("only: they were built without instrumentation, so they report no database time. They are")
        w("outside the completeness matrix and are printed for reference, not compared.")
        versions = sorted({r["target"] for r in historical})
        for rung in rungs:
            w("")
            w(f"### {rung} ms per database command")
            w("")
            w("| workload | " + " | ".join(f"{v} p50" for v in versions) + " | rust p50 |")
            w("|---|" + "---:|" * (len(versions) + 1))
            for workload in WORKLOADS:
                row = []
                for v in versions + ["rust"]:
                    r = cell.get((v, workload, rung))
                    row.append(us(r["latency_us"]["p50"]) if r else "not measured")
                w(f"| `{workload}` | " + " | ".join(row) + " |")

    w("")
    w("## Microbenchmarks")
    w("")
    w("p50 per operation in microseconds, over the frozen corpora. Each record carries the hash of")
    w("the corpus file it ran on.")
    w("")
    families = sorted(FAMILIES)
    corpora = sorted(CORPORA)
    mcell = {(r["target"], r["family"], r["corpus"]["name"]): r for r in micro}
    w("| corpus | " + " | ".join(f"{f} rust | {f} node" for f in families) + " |")
    w("|---|" + "---:|" * (2 * len(families)))
    for corpus in corpora:
        row = []
        for family in families:
            for target in ["rust", "node"]:
                r = mcell.get((target, family, corpus))
                if r is None:
                    fail(f"missing micro cell {target} {family} {corpus}")
                row.append(f"{r['latency_us']['p50']:.3f}")
        w(f"| `{corpus}` | " + " | ".join(row) + " |")
    w("")
    w("## Methods")
    w("")
    for family in families:
        for target in ["rust", "node"]:
            r = next(r for r in micro if r["family"] == family and r["target"] == target)
            w(f"- `{family}`, {target}: {r['method']}")
    print("\n".join(out))


if __name__ == "__main__":
    main()
