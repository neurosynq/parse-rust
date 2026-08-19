#!/usr/bin/env python3
"""Verify that every `File.js:LINE` citation in this repository still resolves at the pin.

This repository's claims about upstream behavior rest on citations into parse-server, and a
citation that silently stops resolving is worse than no citation because it reads as verified.
Upstream moves, so this converts the next drift into a red build instead of something a human has
to notice during review.

**Scans source as well as prose.** The citations live in code comments here, so scanning only a
`docs/` tree meant the check found nothing and passed for the wrong reason, which is exactly the
failure mode it exists to prevent.

What it checks:
  - the cited file exists at the pin
  - the cited file has at least that many lines

What it deliberately does NOT check: whether the line says what the citing text claims. That
needs a human. This catches the mechanical half, which is the half that rots on its own.

Usage:
    python3 tools/check-citations.py            # check
    python3 tools/check-citations.py --list     # also print every resolved citation

Exit status is 0 when every citation resolves, 1 otherwise.
"""

import os
import re
import subprocess
import sys
from collections import defaultdict

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
UPSTREAM = os.path.join(os.path.dirname(REPO), "parse-server")

# `Foo.js:123`, `Foo.ts:123-145`, `src/a/Foo.js:12`, `.releaserc.js:49`.
# The leading guard is a lookbehind rather than `\b` because `\b` refuses to start a match at a
# dot, which silently dropped every dotfile citation until the checker was pointed at one.
CITATION = re.compile(
    r"(?<![\w/.-])((?:[\w./-]+/)?\.?[\w.-]+\.(?:js|ts|jsx|tsx)):(\d+)(?:-(\d+))?\b"
)

# Citations that name a file we cannot resolve because no pin is recorded for its repository.
# These are reported separately and do not fail the build, because there is nothing to check
# them against yet. Record a pin in PIN and they become checkable. Keep this list honest: an
# entry here is an admission that a citation is unverifiable, not a way to silence one.
UNPINNED_HINTS = (
    "s3-adapter", "push-adapter", "Parse-SDK-JS", "node_modules",
    "follow-redirects", "fs-files-adapter",
)

# Basenames belonging to those unpinned repositories. Bare-basename citations cannot be
# attributed by path, so they are listed explicitly rather than guessed at.
FOREIGN_BASENAMES = {
    # Parse JS SDK
    "encode.js", "decode.js", "ParseOp.js", "ParseError.js", "ParseGeoPoint.js",
    "ParseObject.js", "ParsePolygon.js", "ParseFile.js", "ParseACL.js", "ParseQuery.js",
    "ParseUser.js", "ParseSession.js", "ParseRole.js", "ParseRelation.js", "CoreManager.js",
    # parse-server-push-adapter
    "ParsePushAdapter.js", "PushAdapterUtils.js", "APNS.js", "FCM.js", "WEB.js", "EXPO.js",
    # parse-server-s3-adapter and friends
    "optionsFromArguments.js",
}


def read_pin():
    path = os.path.join(REPO, "PIN")
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if line.startswith("parse-server "):
                return line.split()[2]
    sys.exit("PIN: no 'parse-server' entry found")


def tree_index(pin):
    """Map every path at the pin, and every basename, to its full path(s)."""
    out = subprocess.run(
        ["git", "-C", UPSTREAM, "ls-tree", "-r", "--name-only", pin],
        capture_output=True, text=True,
    )
    if out.returncode != 0:
        sys.exit(f"cannot read pin {pin} from {UPSTREAM}:\n{out.stderr.strip()}")
    paths = out.stdout.splitlines()
    by_base = defaultdict(list)
    for p in paths:
        by_base[os.path.basename(p)].append(p)
    return set(paths), by_base


def file_lines(pin, paths):
    """Every cited file at the pin, as a list of lines.

    Returns the content rather than just the count, because the count answers a weaker question
    than it looks like it answers. See `trivial_line`.
    """
    files = {}
    for p in sorted(paths):
        out = subprocess.run(
            ["git", "-C", UPSTREAM, "show", f"{pin}:{p}"],
            capture_output=True, text=True,
        )
        files[p] = [] if out.returncode != 0 else out.stdout.split("\n")
    return files


# Lines that carry no information, so a citation landing on one is almost certainly off by a
# little. Deliberately a small list of exact matches rather than a heuristic: the point is to be
# certain about the ones it flags, because a check that fires on legitimate citations is a check
# people stop reading.
TRIVIAL_LINES = {
    "", "}", "};", "},", "});", "})", ")", ");", "{", "]", "];", "},{",
    "} else {", "else {", "*/", "/*", "//", "return;", "break;", "continue;",
}


def trivial_line(text):
    return text.strip() in TRIVIAL_LINES


def main():
    show_all = "--list" in sys.argv
    pin = read_pin()
    all_paths, by_base = tree_index(pin)

    found = []   # (file, line, cited, lineno)
    # Source first: that is where the citations are. `docs/` is scanned when present, so the same
    # tool works in a checkout that carries the design documents.
    scan_roots = [d for d in ("crates", "tools", "docs") if os.path.isdir(os.path.join(REPO, d))]
    scan_exts = (".rs", ".md", ".js", ".mjs", ".py", ".sh", ".toml", ".yml")
    for top in scan_roots:
      for root, dirs, files in os.walk(os.path.join(REPO, top)):
        dirs[:] = [d for d in dirs if d not in (".git", "node_modules", "target")]
        for name in files:
            if not name.endswith(scan_exts):
                continue
            # This file documents the citation format in its own docstring; those examples are
            # illustrations, not claims about upstream.
            if name == os.path.basename(__file__):
                continue
            full = os.path.join(root, name)
            rel = os.path.relpath(full, REPO)
            with open(full, encoding="utf-8") as fh:
                for i, text in enumerate(fh, start=1):
                    for m in CITATION.finditer(text):
                        cited, start, end = m.group(1), int(m.group(2)), m.group(3)
                        # Two line numbers, deliberately. The **last** line of a range is what the
                        # past-EOF check needs; the **first** is what the citation actually points
                        # at, and the only one whose content is meaningful. A range covers a block,
                        # so its last line is usually a closing brace: checking that one flagged
                        # half of every citation in the repository the first time this was written.
                        found.append((rel, i, cited, max(start, int(end or start)), start))

    # Resolve each cited name to a path at the pin.
    wanted, unresolved, skipped, ambiguous = {}, [], [], []
    for rel, docline, cited, lineno, startline in found:
        if any(h in cited for h in UNPINNED_HINTS) or os.path.basename(cited) in FOREIGN_BASENAMES:
            skipped.append((rel, docline, cited))
            continue
        # Citations come in three styles, all legitimate and all in use:
        #   full     src/Controllers/DatabaseController.js:1410
        #   partial  Options/Definitions.js:1370          (relative to the repo root or to src/)
        #   bare     RestWrite.js:1204
        # Resolve by longest-suffix match, which handles all three uniformly. Matching on the
        # whole cited path rather than just its basename is what keeps `follow-redirects/index.js`
        # from silently "resolving" to `src/Controllers/index.js`.
        probe = cited
        for prefix in ("../parse-server/", "parse-server/"):
            if probe.startswith(prefix):
                probe = probe[len(prefix):]
                break

        if probe in all_paths:
            wanted.setdefault(probe, []).append((rel, docline, lineno, startline))
            continue

        cands = [p for p in by_base.get(os.path.basename(probe), []) if p.endswith("/" + probe)]
        # A bare basename matches on basename alone.
        if "/" not in probe:
            cands = by_base.get(probe, [])
        # Prefer src/ over spec/ fixtures, which are never what a design document means.
        pool = [c for c in cands if c.startswith("src/")] or cands

        if len(pool) == 1:
            wanted.setdefault(pool[0], []).append((rel, docline, lineno, startline))
        elif not pool:
            unresolved.append((rel, docline, cited))
        else:
            ambiguous.append((rel, docline, cited, pool))

    files = file_lines(pin, wanted.keys())
    counts = {p: len(l) for p, l in files.items()}

    # **A resolved citation is not a correct one, and until this check the difference was
    # invisible.** Everything above asks whether the file and the line exist at the pin. It does
    # not read the line, so a citation off by one resolves cleanly forever: three in `cors.rs`
    # pointed at `Access-Control-Allow-Headers`, a blank line and a `} else {` while every run
    # reported them resolved.
    #
    # Reading the line and judging whether it *supports the claim* needs to know what the claim is,
    # which is not something this can do. What it can do is catch the case where the line says
    # nothing at all: a closing brace or a blank line is never what a citation means, so landing on
    # one is a mistake regardless of what the surrounding comment asserts. That is a floor, not a
    # guarantee, and it is worth having precisely because two of those three were exactly this.
    overruns, trivial = [], []
    for path, uses in wanted.items():
        for rel, docline, lineno, startline in uses:
            if lineno > counts.get(path, 0):
                overruns.append((rel, docline, path, lineno, counts.get(path, 0)))
            elif 1 <= startline <= counts.get(path, 0) and trivial_line(files[path][startline - 1]):
                trivial.append(
                    (rel, docline, path, startline, files[path][startline - 1].strip())
                )

    total = len(found)
    ok = total - len(unresolved) - len(overruns) - len(skipped) - len(ambiguous) - len(trivial)
    print(f"pin {pin}")
    print(f"citations: {total}  resolved: {ok}  unresolved: {len(unresolved)}  "
          f"past-eof: {len(overruns)}  ambiguous: {len(ambiguous)}  "
          f"blank-or-brace: {len(trivial)}  skipped(unpinned): {len(skipped)}")

    if show_all:
        for path, uses in sorted(wanted.items()):
            print(f"  {path} ({counts.get(path, 0)} lines) <- {len(uses)} citation(s)")

    if unresolved:
        print("\nNO SUCH FILE AT THE PIN:")
        for rel, docline, cited in sorted(set(unresolved)):
            print(f"  {rel}:{docline}  ->  {cited}")

    if overruns:
        print("\nCITED LINE IS PAST END OF FILE:")
        for rel, docline, path, lineno, have in sorted(set(overruns)):
            print(f"  {rel}:{docline}  ->  {path}:{lineno} (file has {have} lines)")

    if ambiguous:
        print("\nAMBIGUOUS BASENAME (cite a path, not a bare filename):")
        for rel, docline, cited, pool in sorted(set((a, b, c, tuple(d)) for a, b, c, d in ambiguous)):
            print(f"  {rel}:{docline}  ->  {cited}  matches {len(pool)}: {', '.join(pool[:4])}")

    if skipped:
        uniq = sorted(set(c for _, _, c in skipped))
        print(f"\nSKIPPED, no pin recorded for their repository ({len(uniq)} distinct):")
        for c in uniq[:10]:
            print(f"  {c}")

    # A scan that finds nothing is a failure, not a pass. This checker once scanned only a `docs/`
    # tree that does not exist in this repository: it reported zero citations, exited 0, and read
    # as a green check while 33 real citations sat unverified in the code. Finding nothing means
    # the scan roots are wrong, which is the one failure this tool cannot afford to be quiet about.
    if total == 0:
        print("\nFOUND NO CITATIONS AT ALL. The scan roots are wrong, or the extensions are.")
        print(f"  scanned: {', '.join(scan_roots) or '(nothing)'}")
        return 1

    if trivial:
        print()
        print("citations landing on a blank line or a bare brace. The line exists, so every other")
        print("check passes; it just does not say anything, which means the number is off:")
        for rel, docline, path, lineno, text in sorted(set(trivial)):
            shown = text if text else "(blank)"
            print(f"  {rel}:{docline} -> {path}:{lineno} is {shown}")

    return 1 if (unresolved or overruns or ambiguous or trivial) else 0


if __name__ == "__main__":
    sys.exit(main())
