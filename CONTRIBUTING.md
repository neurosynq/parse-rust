# Contributing to parse-rust

Thanks for considering it. This document covers the terms your contribution arrives under, and
then how to actually work on the code.

## Contributor terms

Apache License 2.0, section 5, already covers this: a contribution you intentionally submit for
inclusion in the project arrives under the same licence as the project, unless you explicitly say
otherwise. Nothing further to sign.

You keep your copyright. You remain free to use your own contribution anywhere else.

## What this project is

A Rust reimplementation of Parse Server. The contract is **wire compatibility**: an unmodified
Parse SDK pointed at parse-rust should behave exactly as it does against parse-server. Same
routes, same JSON shapes, same error codes, same header semantics.

That single sentence explains most of what look like odd decisions in the codebase.

## The rules that matter most

**Never answer a question about Parse Server behavior from memory.** Parse's behavior is
under-documented and the edge cases are exactly where the surprises live. Read the upstream source
at the pinned commit and cite it:

```
git -C ../parse-server show $(awk '/^parse-server /{print $3}' PIN):src/Controllers/DatabaseController.js
```

A claim about upstream in a comment or a commit message carries a `File.js:LINE` citation against
that pin. During this project's development, source-derived claims about parse-server turned out
to be wrong often enough that the citation habit is not ceremony.

**Error codes and messages are API.** `spec/` asserts on them. Never invent a code, and never
"improve" a message. If a message reads badly, it probably matches upstream exactly.

**`UPSTREAM-QUIRK:` comments are load-bearing.** They mark behavior reproduced deliberately even
though it looks wrong. Removing one because it seems like a bug is how a wire-compatibility
regression gets introduced in good faith. If you think one is wrong, prove it against the pin.

**The reasoning lives in the code.** There is no `docs/` tree here. If your change needs
explanation, the explanation goes in a comment next to the code, not in a document and not only in
the PR description. Never cite a file that is not in this repository.

**Bug-compatibility stops at data leaks.** Where upstream behavior is wire-visible but the
visible behavior is unauthorised disclosure, implement the safe behavior, note the difference at
the call site, and say which spec files it turns red.

**No panics in request paths.** No `unwrap()`, `expect()`, or slice indexing where a malformed
request from an untrusted client can reach it. A bad request must never take down a worker. The
lint is scoped to non-test builds; tests may assert however they like.

## Working on it

```
cargo build --workspace
tools/test.sh              # everything available on this machine
tools/test.sh --quick      # skip steps needing node, MongoDB or an upstream checkout
```

Several suites compare against a real parse-server checkout, expected as a sibling directory
(`../parse-server`) or wherever `PARSE_SERVER_ROOT` points. They skip with a stated reason when it
is absent rather than silently passing.

Run `tools/test.sh` before opening a pull request. **It is a superset of what CI runs**, not the
same set. CI has only the `parse` npm SDK, not an upstream parse-server checkout, so it cannot boot
a real parse-server and cannot run:

- Gate B, data fidelity, which boots one on the same database.
- Gate D, shared auth state, likewise.
- Gates E and I, stock configuration, which boot servers of their own at several configurations.
- The upstream half of Gate C, which is the half that makes it a comparison rather than a
  self-check. CI runs the parse-rust half only.
- Gate F, upstream's own spec files, and Gate H, its reconfigure control plane, both of which run
  against parse-server built at the pin as well as against parse-rust.
- The differentials that compare against upstream's own modules: bcrypt interop, the
  `MongoTransform` oracle and the `_SCHEMA` format oracle.

Those run only locally, and CI names each one it skips rather than passing quietly. A green CI run
therefore means less than a green local run, and in particular says nothing about whether
parse-rust and parse-server agree.

### Tests

Prefer a test that compares against the real thing over one that asserts your own reading. The
differential suites exist because that distinction has repeatedly mattered: the number formatter,
bcrypt interop, the Parse/BSON transform and the `_SCHEMA` type strings are all checked against
actual parse-server behavior rather than against expectations someone typed in. More than one bug
in this codebase was found that way and would not have been found otherwise.

Gates A to D drive the whole flow through the unmodified Parse SDK. **Gates E and I are the
exception and have to be**: they select the socket's source address per request, which the SDK gives
no way to do, so they speak raw `node:http`. Gate A is the signup-to-logout flow; Gate B compares
stored BSON types against a real parse-server on the same database; Gate C replays the authorization
model against both servers and requires them to agree assertion for assertion; Gate D puts both
servers on one database and checks that sessions, roles and `_SCHEMA` documents cross; Gates E and I
boot their own servers at several configurations and from two source addresses, and run each
assertion against both, stating each server's answer where parse-rust deliberately differs. Gate F
runs upstream's own spec files against both servers; Gate H checks the reconfigure control plane
they use; Gate J benchmarks the two (`tools/bench/gate-j.sh`); Gate K brings the demo up from a
fresh clone (`tools/demo/check.sh`). If you change behavior a client can observe, a gate should
notice.

Three rules they live by, all of them scars. **Assert that a caller can see its own data before
asserting it cannot see anyone else's**, or a server that hides everything passes. **Each gate
carries a floor on how many assertions it executed**, because a runner that finds nothing exits
zero. And **a floor covering more than one subject must be per subject**: Gate E's first version had
one floor of 44 over 60 assertions split 16 and 44, so deleting its entire master-key half left
exactly 44 and reported green. Raise a count when you add assertions; never lower one to make a run
pass.

**Never bind a fixed port in a test.** Bind `0` and read back the address. Test batteries get run
in parallel, so a fixed port collides with another copy of itself, and the failure looks like
flakiness rather than a port conflict. Poll for readiness; never sleep.

### Style

- No emojis, anywhere.
- No em dashes. Use a comma, colon, semicolon, parentheses, or another sentence.
- No vanity statistics. Do not cite line counts, test counts or diff sizes as evidence of effort.
  Numbers that carry real meaning (measured timings, thresholds, benchmark results, counts of
  actual findings) are welcome.
- Short declarative sentences. Say the thing and stop.
- Match the surrounding code's comment density and idiom.

### Commits and pull requests

Explain *why*, not *what*. The diff shows what changed. A good message says what upstream
behavior is being matched, or what breaks without the change.

Keep a pull request to one concern. A wire-behavior change and a refactor in the same PR means
neither gets reviewed properly.

## Reporting a security issue

Please do not open a public issue for a security problem in parse-rust. Open a private security
advisory on the repository instead.

For vulnerabilities in **Parse Server itself**, report them to the Parse Platform maintainers
through their own security process rather than here.
