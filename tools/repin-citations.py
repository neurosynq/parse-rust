#!/usr/bin/env python3
"""Carry every `File.js:LINE` citation from one upstream pin to another.

`check-citations.py` catches a citation that lands on a blank line or a brace after a re-pin. It
cannot catch one that shifted onto a different line that still says something, which after a
large re-pin is most of them. This maps each cited line through a diff of the file at the two
revisions instead of guessing.

Three outcomes per citation:
  - **moved**: every cited line exists unchanged at the new pin. The number is rewritten in place.
  - **changed**: a cited line was edited or deleted upstream. Rewritten to the nearest surviving
    position and listed, because the claim the citation supports may no longer hold. A human
    reads each one.
  - **interior**: a range whose endpoints survived but whose interior was edited. Rewritten and
    listed, since the block it cites now contains something it did not.

Usage:
    python3 tools/repin-citations.py OLD_SHA            # report only
    python3 tools/repin-citations.py OLD_SHA --write    # rewrite citations in place

NEW is read from PIN, so update PIN first. Run `check-citations.py` afterwards.
"""

import difflib
import importlib.util
import os
import subprocess
import sys
from collections import defaultdict

HERE = os.path.dirname(os.path.abspath(__file__))
spec = importlib.util.spec_from_file_location("cc", os.path.join(HERE, "check-citations.py"))
cc = importlib.util.module_from_spec(spec)
spec.loader.exec_module(cc)


def show(sha, path):
    out = subprocess.run(["git", "-C", cc.UPSTREAM, "show", f"{sha}:{path}"],
                         capture_output=True, text=True)
    return None if out.returncode != 0 else out.stdout.split("\n")


def line_map(old, new):
    """Old 1-based line -> (new 1-based line, survived unchanged)."""
    sm = difflib.SequenceMatcher(None, old, new, autojunk=False)
    m = {}
    for tag, i1, i2, j1, j2 in sm.get_opcodes():
        for k in range(i1, i2):
            if tag == "equal":
                m[k + 1] = (j1 + (k - i1) + 1, True)
            else:
                # Nearest surviving position: the start of the replacement, clamped into it.
                off = min(k - i1, max(j2 - j1 - 1, 0))
                m[k + 1] = (j1 + off + 1, False)
    return m


def resolve(cited, all_paths, by_base):
    if any(h in cited for h in cc.UNPINNED_HINTS) or os.path.basename(cited) in cc.FOREIGN_BASENAMES:
        return None
    probe = cited
    for prefix in ("../parse-server/", "parse-server/"):
        if probe.startswith(prefix):
            probe = probe[len(prefix):]
    if probe in all_paths:
        return probe
    if "/" not in probe:
        cands = by_base.get(probe, [])
    else:
        cands = [p for p in by_base.get(os.path.basename(probe), []) if p.endswith("/" + probe)]
    pool = [c for c in cands if c.startswith("src/")] or cands
    return pool[0] if len(pool) == 1 else None


def main():
    if len(sys.argv) < 2:
        sys.exit(__doc__)
    old_sha, write = sys.argv[1], "--write" in sys.argv
    new_sha = cc.read_pin()
    old_paths, old_base = cc.tree_index(old_sha)
    new_paths, _ = cc.tree_index(new_sha)

    maps, gone = {}, set()

    def mapping(path):
        if path not in maps:
            old, new = show(old_sha, path), show(new_sha, path)
            if old is None or new is None:
                gone.add(path)
                maps[path] = None
            else:
                maps[path] = line_map(old, new)
        return maps[path]

    report = defaultdict(list)
    roots = [d for d in ("crates", "tools", "docs") if os.path.isdir(os.path.join(cc.REPO, d))]
    for top in roots:
        for root, dirs, files in os.walk(os.path.join(cc.REPO, top)):
            dirs[:] = [d for d in dirs if d not in (".git", "node_modules", "target")]
            for name in files:
                if not name.endswith((".rs", ".md", ".js", ".mjs", ".py", ".sh", ".toml", ".yml")):
                    continue
                if name in ("check-citations.py", os.path.basename(__file__)):
                    continue
                full = os.path.join(root, name)
                rel = os.path.relpath(full, cc.REPO)
                with open(full, encoding="utf-8") as fh:
                    lines = fh.read().split("\n")
                dirty = False
                for i, text in enumerate(lines):
                    def sub(mt):
                        nonlocal dirty
                        cited, a, b = mt.group(1), int(mt.group(2)), mt.group(3)
                        path = resolve(cited, old_paths, old_base)
                        if path is None:
                            return mt.group(0)
                        m = mapping(path)
                        if m is None:
                            report["file gone"].append(f"{rel}:{i+1} -> {cited}:{a}")
                            return mt.group(0)
                        end = int(b) if b else a
                        if a not in m or end not in m:
                            report["past eof at old pin"].append(f"{rel}:{i+1} -> {cited}:{a}")
                            return mt.group(0)
                        na, oka = m[a]
                        ne, oke = m[end]
                        interior = all(m.get(k, (0, False))[1] for k in range(a, end + 1))
                        if not (oka and oke):
                            report["changed"].append(f"{rel}:{i+1} -> {path}:{a} => {na}")
                        elif not interior or (ne - na) != (end - a):
                            report["interior"].append(f"{rel}:{i+1} -> {path}:{a}-{end} => {na}-{ne}")
                        else:
                            report["moved" if na != a else "unchanged"].append(rel)
                        out = f"{cited}:{na}" + (f"-{ne}" if b else "")
                        if out != mt.group(0):
                            dirty = True
                        return out
                    lines[i] = cc.CITATION.sub(sub, text)
                if dirty and write:
                    with open(full, "w", encoding="utf-8") as fh:
                        fh.write("\n".join(lines))

    print(f"{old_sha[:10]} -> {new_sha[:10]}")
    for k in ("unchanged", "moved"):
        print(f"{k}: {len(report[k])}")
    for k in ("changed", "interior", "file gone", "past eof at old pin"):
        print(f"\n{k.upper()}: {len(report[k])}")
        for r in report[k]:
            print(f"  {r}")
    if not write:
        print("\n(report only; pass --write to rewrite)")


if __name__ == "__main__":
    main()
