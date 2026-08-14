# parse-rust

**Parse Server, rebuilt in Rust.**

An embeddable, Rust-native implementation designed for wire and MongoDB compatibility with
[Parse Server](https://github.com/parse-community/parse-server).

**Unofficial.** Not affiliated with, endorsed by, or sponsored by Parse Community. Parse and Parse
Server are trademarks of their respective owners.

## Status: work in progress

**This is an early proof of concept, and the intent is to finish it.** Parse Server is a large
surface and parse-rust currently covers a thin slice of it: enough that an unmodified Parse SDK
can sign up, log in, create an object, update a field, query it back and fetch it by id against
MongoDB, and enough that the rows it writes are interchangeable with parse-server's on the same
database. That is the whole of the 0.1.0 claim. Everything else is ahead of it, not behind it.

**Not production software.** Single node, MongoDB only, no security guarantee, and most of Parse's
surface is absent. Do not point it at data you care about.

The project exists to reach parity, not to demonstrate a subset. Each release should move a
subsystem out of the second list below and into the first, and `CHANGELOG.md` records what moved.

### What works today

| Area | Endpoints and behavior |
|---|---|
| Objects | `POST`, `GET`, `PUT`, `DELETE` on `/classes/:class`, and `GET` with `where`, `limit`, `skip`, `order`, `keys`, `count` |
| Users | `POST /users` (signup, bcrypt), `POST /login`, `GET /users/me`, `POST /logout` |
| Sessions | Session tokens in upstream's `r:` format, resolved on every request |
| Access control | Object ACLs enforced on read, write and delete, stored as `_rperm` and `_wperm` |
| Schema | Classes and fields created by first write, types inferred, later writes checked against them |
| Types | Pointer, Date, Bytes, GeoPoint, File, Polygon, Relation and the update operations, encoded as upstream encodes them |
| Errors | Upstream's numeric codes, messages and both error envelopes |
| Transport | The JavaScript SDK's `POST`-everything form, normalized before routing |
| Server | `GET /serverInfo`, `GET /health`, master and maintenance key gates, client-key validation |

### What is not there yet

LiveQuery, Cloud Code and triggers, files, push, aggregate, batch, GraphQL, `include`, relation
queries, roles, password reset, email verification, auth adapters, MFA, rate limiting,
idempotency, CLP, the schema API, and PostgreSQL.

Three of those absences are not inert, and matter before you try anything against real data:

- **Roles are not implemented**, so a `role:` ACL entry never matches and therefore *denies*. That
  is fail-closed and safe, but pointing this at a database with role-based ACLs will look like
  data has gone missing.
- **Sessions live in memory.** Restarting the server logs everyone out, and two processes do not
  share sessions.
- **Retried writes duplicate**, because idempotency is not implemented. This matches upstream's
  default configuration, where the feature is off unless paths are configured.

`CHANGELOG.md` carries the full list, including the deliberate differences from upstream.

### Where this is going

Roughly in order. Each step is gated on the upstream spec files for that subsystem passing, not on
the code existing.

1. **Core loop.** Finish what 0.1.0 started: CLP, the schema API, batch, `include`, relations,
   persisted sessions, and the schema race that concurrent first writes can still lose.
2. **Auth and users.** Roles, password reset, email verification, auth adapters, MFA, account
   lockout.
3. **Triggers.** A `TriggerHost` trait with native Rust triggers and a webhook host. Existing
   `main.js` cloud code runs in a Node sidecar reached over that same webhook protocol, so
   JavaScript is a compatibility path rather than a requirement.
4. **Realtime and files.** LiveQuery and its pubsub, the files adapter, GridFS.
5. **Push, aggregate, hooks, pages, security checks.**
6. **GraphQL**, last: the largest surface and the smallest share of real usage.

PostgreSQL is a first-class planned backend rather than an afterthought. The storage trait is
shaped by two backends today even though only one is implemented, on the principle that a trait
built against a single backend bakes that backend's assumptions in.

## What parity means

The contract is **wire compatibility**, not source fidelity. An unmodified Parse SDK pointed at
parse-rust should behave exactly as it does against parse-server: same routes, same JSON shapes,
same error codes, same header semantics.

Where idiomatic Rust and a literal port disagree, idiomatic Rust wins, as long as the observable
behavior over the wire is byte-identical. Internal structure is free. The external surface is not.

That contract is why the tests look the way they do. Everything that touches upstream behavior is
checked against upstream rather than against someone's reading of it: the ECMAScript number
formatter against Node, bcrypt in both directions against the module parse-server loads, the
Parse/BSON transform against upstream's own `MongoTransform`, the `_SCHEMA` type strings against
what parse-server actually writes into MongoDB, and the acceptance gates against a running
parse-server.

## Quick start

Requires a stable Rust toolchain and a MongoDB you can write to. Anything 7.0 or later; a single
node is fine, no replica set needed.

```
cargo build --release

PARSE_SERVER_APPLICATION_ID=your-app-id \
PARSE_SERVER_MASTER_KEY=a-long-random-secret \
PARSE_SERVER_DATABASE_URI=mongodb://127.0.0.1:27017/parse_rust_demo \
PORT=27800 \
./target/release/parse-rust
```

The application id and master key are **required and have no defaults**. The master key bypasses
every access control, so a server that starts without one configured would answer to whatever
value the documentation happened to suggest. Refusing to start is the safer failure.

It prints the address it bound:

```
parse-rust listening on http://127.0.0.1:27800
```

Set `PORT=0` to bind an ephemeral port and read the actual one off that line. That is what every
test does, so parallel runs never collide, and it also lets parse-rust run beside a real
parse-server. The default is 27800 rather than Parse's 1337 for the same reason.

It listens on loopback unless told otherwise. `PARSE_SERVER_HOST` is upstream's option name and is
honored, but the default here is `127.0.0.1` rather than upstream's `0.0.0.0`, so a half-built
server cannot end up on a network by accident. Set it to `0.0.0.0` in a container.

### Configuration

Environment variables only for now. Upstream has roughly 292 options and this is the slice that
has behavior behind it; the names are upstream's, so they carry over.

| Variable | Default | |
|---|---|---|
| `PARSE_SERVER_APPLICATION_ID` | none | **required** |
| `PARSE_SERVER_MASTER_KEY` | none | **required** |
| `PARSE_SERVER_DATABASE_URI` | `mongodb://127.0.0.1:27017/parse` | |
| `PORT` | `27800` | `0` binds an ephemeral port and prints it |
| `PARSE_SERVER_HOST` | `127.0.0.1` | upstream defaults to `0.0.0.0`; set that in a container |
| `PARSE_SERVER_MOUNT_PATH` | `/parse` | |
| `PARSE_SERVER_JAVASCRIPT_KEY` | unset | if set, non-master requests must present a client key |
| `PARSE_SERVER_REST_API_KEY` | unset | same |

The client keys are all-or-nothing, as upstream: configure none and none is required; configure
any one and every non-master request must present a matching key.

```
curl -s http://127.0.0.1:27800/parse/health
{"status":"ok"}
```

### With the JavaScript SDK

Nothing about the SDK is modified or specially configured.

```js
const Parse = require('parse/node');
Parse.initialize('your-app-id');
Parse.serverURL = 'http://127.0.0.1:27800/parse';

const user = new Parse.User();
user.set('username', 'alice');
user.set('password', 'hunter2');
await user.signUp();

const Note = Parse.Object.extend('Note');
const note = new Note();
note.set('title', 'hello');
note.set('views', 1);
await note.save();

note.set('views', 2);
await note.save();

const q = new Parse.Query(Note);
q.equalTo('title', 'hello');
console.log((await q.find()).map(o => o.get('views')));   // [ 2 ]
```

The SDK does not send the REST API the documentation describes. Every call is a `POST` with a
`text/plain` body, and the method, the credentials and the query parameters all travel inside that
body so a browser never sends a CORS preflight. parse-rust normalizes that the way upstream does.
You do not need to know this to use it, but it is why "point the SDK at it" is a stronger claim
than "the endpoints exist".

### With curl

```
BASE=http://127.0.0.1:27800/parse
H=(-H 'Content-Type: application/json' -H 'X-Parse-Application-Id: your-app-id')

curl -s "${H[@]}" -X POST "$BASE/users"   -d '{"username":"alice","password":"hunter2"}'
curl -s "${H[@]}" -X POST "$BASE/login"   -d '{"username":"alice","password":"hunter2"}'

T='r:…'   # the sessionToken from above
curl -s "${H[@]}" -H "X-Parse-Session-Token: $T" -X POST "$BASE/classes/Note" -d '{"title":"hello","views":3}'
curl -s "${H[@]}" -H "X-Parse-Session-Token: $T" -X PUT  "$BASE/classes/Note/<id>" -d '{"views":4}'
curl -s -G "${H[@]}" -H "X-Parse-Session-Token: $T" "$BASE/classes/Note" --data-urlencode 'where={"title":"hello"}'
```

Note what a login response does *not* contain: no `password`, and no `_hashed_password`. Every
response is filtered so that no `_`-prefixed key can reach a client.

The class does not need to exist before the first write. That write creates it and infers each
field's type, and every later write is checked against those types:

```
curl -s "${H[@]}" -X POST "$BASE/classes/Note" -d '{"title":42}'
{"code":111,"error":"schema mismatch for Note.title; expected String but got Number"}
```

That message is byte-for-byte upstream's. Error codes and messages are API here, not diagnostics.

## Architecture

A Cargo workspace whose crate boundaries mirror upstream subsystem boundaries, so a change
upstream maps to an obvious place here.

```
parse-rust-core      Parse types, error codes, JSON encoding. No I/O.
parse-rust-schema    Field types, inference, validation, the _SCHEMA storage format.
parse-rust-storage   StorageAdapter trait and the query AST adapters lower.
parse-rust-mongo     MongoDB adapter and the Parse/BSON transform.
parse-rust-rest      The read and write pipelines.
parse-rust-auth      Password hashing; sessions and roles to follow.
parse-rust-server    Library. Router, middleware, config. What you depend on.
parse-rust-cli       Installs the `parse-rust` executable, and nothing else.
```

The project, the repository, this README and the executable are all **parse-rust**. Only the
Cargo package names carry a qualifier, because the normalized registry name `parse-rust` is
already occupied on crates.io by [an unrelated string-parsing
crate](https://crates.io/crates/parse_rust), and crates.io treats `parse-rust` and `parse_rust` as
one name. Nothing is published yet.

**A library first, with a thin binary on top.** Native Rust triggers will require a deployment to
compile its own binary, and adapters are registered through a builder rather than resolved from a
module name, so the primary artifact is something you link against.

**The storage trait is shaped by two backends, not one.** It takes a query AST rather than a Mongo
query document, because handing a Mongo document to a SQL backend means writing a Mongo
interpreter in SQL. The rule: if a method can only be implemented sensibly for one backend, the
trait is wrong.

## Testing

```
tools/test.sh            # everything available on this machine
tools/test.sh --quick    # skip steps needing node, MongoDB or an upstream checkout
```

Steps that need more than a Rust toolchain skip with a stated reason rather than silently passing.

Several suites compare against a real parse-server checkout. They expect it as a sibling directory
(`../parse-server`), or wherever `PARSE_SERVER_ROOT` points. The two acceptance gates are:

- **Gate A** drives the whole flow through the unmodified `parse` npm SDK, including ACL round
  trips, cross-user read and write isolation, and rejection of invalid session tokens.
- **Gate B** points parse-rust *and* a real parse-server at the same database, writes with each,
  reads with the other, and compares the stored BSON types rather than just the values. Values
  alone would not catch the Int32-versus-Double rule, since both read back as the same JavaScript
  number.

Both gates are also run against a real parse-server, so a failure means parse-rust diverged rather
than that an expectation was invented.

## Reference implementation

Parse Server 9.10.1-alpha.6 is the target, pinned at the commit recorded in `PIN`. Claims about
upstream behavior in this codebase carry a `File.js:LINE` citation against that pin rather than a
recollection, because Parse's behavior is under-documented and the edge cases are exactly where
the surprises are.

```
git -C ../parse-server show $(awk '/^parse-server /{print $3}' PIN):src/Controllers/DatabaseController.js
```

Comments marked `UPSTREAM-QUIRK:` record behavior that is reproduced deliberately even though it
looks wrong. Those are load-bearing. Removing one because it reads oddly is how a
wire-compatibility bug gets reintroduced in good faith.

## Differences from upstream

Not every difference is a defect, but an undocumented one is. Deliberate differences are recorded
in the code at the point where they apply, with the upstream citation showing what is being
diverged from, and summarized per release in `CHANGELOG.md`.

One standing rule: bug-compatibility does not extend to upstream behavior that leaks data. Where a
quirk is wire-visible but the visible behavior is unauthorized disclosure, parse-rust implements
the safe behavior and says so at the call site.

## Contributing

See `CONTRIBUTING.md`. Contributions arrive under Apache-2.0 by way of section 5 of the licence,
so there is nothing extra to sign.

## License

Apache License 2.0. See `LICENSE`.

parse-rust is a **derivative work** of Parse Server rather than an independent clean-room
implementation: its behavior, wire protocol, error codes and configuration surface are derived
from the Parse Server source, which is licensed under Apache 2.0. `NOTICE` records that and is
part of the licensing terms rather than a courtesy.

Parse and Parse Server are trademarks of their respective owners. This project is not affiliated
with, endorsed by, or sponsored by Parse Community.
