# parse-rust

**Parse Server, rebuilt in Rust.**

An embeddable, Rust-native implementation designed for wire and MongoDB compatibility with
[Parse Server](https://github.com/parse-community/parse-server).

**Unofficial.** Not affiliated with, endorsed by, or sponsored by Parse Community. Parse and Parse
Server are trademarks of their respective owners.

## Status: work in progress

**This is an early implementation, and the intent is to finish it.** Parse Server is a large
surface and parse-rust covers a slice of it. 0.1.0 showed that an unmodified Parse SDK could sign
up, log in, create an object, update a field, query it back and fetch it by id against MongoDB,
and that the rows it wrote were interchangeable with parse-server's on the same database.

0.2.0 is the authorization milestone, and it changes what the database can be. Roles resolve,
class-level permissions are evaluated, pointer permissions narrow queries, protected fields are
stripped, and the sessions, roles and join tables it writes are the rows parse-server reads from
the same database. 0.1.0 could talk to a Parse client; 0.2.0 can be pointed at a Parse database.

0.2.1 closes the stock-configuration gaps found while testing that milestone: the master key is
limited to loopback unless `masterKeyIps` says otherwise, CLP-declared default ACLs are applied on
create, and falsy or object-shaped `_User` ACLs no longer leave the row public or remove its
owner's access.

0.3.0, implemented and not yet released, is the conformance milestone. parse-rust is now measured
against parse-server's own test suite rather than only against tests this project wrote for itself:
upstream's spec files run block by block against a parse-rust process, with a server-less control
run and parse-server itself as the reference. It adds the read surface those files need first (geo
queries, `$text`, `explain`, `hint` and `comment`), a benchmark harness, and a one-command demo.
Everything else is ahead of that, not behind it.

**Not production software.** Single node, MongoDB only, no security guarantee, and most of Parse's
surface is absent. Do not point it at data you care about.

The project exists to reach parity, not to demonstrate a subset. Each release should move a
subsystem out of the second list below and into the first, and `CHANGELOG.md` records what moved.

### What works today

| Area | Endpoints and behavior |
|---|---|
| Objects | `POST`, `GET`, `PUT`, `DELETE` on `/classes/:class`, and `GET` with `where`, `limit`, `skip`, `order`, `keys`, `excludeKeys`, `count` |
| Queries | `$or`, `$and`, `$nor`, `$regex` with `$options`, `$all`, `$relatedTo`, `include` with dotted paths, geo (`$nearSphere`, `$within`, `$geoWithin`, `$geoIntersects`), `$text`, and `explain`, `hint` and `comment` |
| Users | `POST /users` (signup, bcrypt), `POST /login`, `GET /users/me`, `POST /logout`, and account lockout |
| Installations | `/classes/_Installation` with upstream's write checks; not its deduplication |
| Sessions | `_Session` rows in upstream's format, surviving a restart and readable by parse-server. `/sessions` with `me`, list, get and delete |
| Roles | `_Role` with its `users` and `roles` relations, the five `/roles` verbs, and transitive role graph expansion |
| Access control | Object ACLs, class-level permissions with pointer permissions and default ACLs, and `protectedFields` |
| Schema | Classes and fields created by first write with types inferred, plus the full `/schemas` API and `/purge`, master-key only |
| Relations | `_Join` tables, `AddRelation` and `RemoveRelation`, and constraints on a `Relation`-typed field |
| Writes | The atomic update operations: `Increment`, `Add`, `AddUnique`, `Remove`, `Delete` |
| Batch | `/batch` with per-operation results and upstream's error shape |
| Types | Pointer, Date, Bytes, GeoPoint, File, Polygon, Relation and the update operations, encoded as upstream encodes them |
| Errors | Upstream's numeric codes, messages and both error envelopes |
| Transport | The JavaScript SDK's `POST`-everything form, normalized before routing |
| Server | `GET /serverInfo`, `GET /health`, the master key gate with source-address filtering, client-key validation |
| Browsers | Upstream's CORS headers on every response including errors, and an `OPTIONS` preflight answered directly. `allowOrigin` and `allowHeaders` are configurable |

### What is not there yet

LiveQuery, Cloud Code and triggers, files, push, aggregate, GraphQL, `$inQuery`, `$notInQuery`,
`$select`, `$dontSelect`, `$score` ordering, password reset, email verification, auth adapters,
MFA, password policy, rate limiting, idempotency, and PostgreSQL. Of
the `_User` routes, `/users/:objectId` does not exist and `/classes/_User` refuses an ordinary
client's create and delete, so `signUp`, `logIn` and `user.save()` on an existing user all work,
while creating or deleting a user outside `POST /users` does not.

Three of those absences are not inert, and matter before you try anything against real data:

- **Retried writes duplicate**, because idempotency is not implemented. This matches upstream's
  default configuration, where the feature is off unless paths are configured.
- **Query constraints that are not implemented are refused, not ignored.** A request using
  `$inQuery` or `$select` gets an error naming the operator. That is deliberate: a
  silently dropped constraint broadens a result set, which is an authorization failure rather than
  a missing feature. Code written against parse-server will fail loudly here rather than return
  too much.
- **Schemas are cached; roles are not.** A schema change made through this server applies to the
  next request, and one made by another server sharing the database waits for
  `PARSE_SERVER_DATABASE_SCHEMA_CACHE_TTL` or a restart, as it does between parse-server nodes.
  Role expansion issues one query per level of the graph on every request.

`CHANGELOG.md` carries the full list, including the deliberate differences from upstream.

### Where this is going

Roughly in order. Each step should be gated on the upstream spec files for that subsystem passing,
not on the code existing, which is why the first item is the instrument rather than a feature.

1. **The conformance harness.** Built in 0.3.0. Parse Server ships an executable specification,
   and `tools/conformance/run.mjs` now runs it against parse-rust. Coverage grows file by file.
2. **Auth and users.** Password reset, email verification, auth adapters, MFA, account lockout,
   password policy. Account lockout landed in 0.3.0.
3. **Triggers.** A `TriggerHost` trait with native Rust triggers and a webhook host. Existing
   `main.js` cloud code runs in a Node sidecar reached over that same webhook protocol, so
   JavaScript is a compatibility path rather than a requirement.
4. **Realtime and files.** LiveQuery and its pubsub, the files adapter, GridFS.
5. **Push, aggregate, hooks, pages, security checks.**
6. **GraphQL**, last: the largest surface and the smallest share of real usage.

0.1.0, 0.2.0 and 0.2.1 are done, and 0.3.0 is implemented; `CHANGELOG.md` says what each one
actually landed.

PostgreSQL is a first-class planned backend rather than an afterthought. The storage trait is
shaped by two backends today even though only one is implemented, on the principle that a trait
built against a single backend bakes that backend's assumptions in.

## What parity means

The contract is **wire compatibility**, not source fidelity. An unmodified Parse SDK pointed at
parse-rust should behave exactly as it does against parse-server: same routes, same JSON shapes,
same error codes, same header semantics.

The requirement is semantic identity, with exact values wherever a client depends on them. Error
codes and messages, field names, field ordering within an object, date encoding, `objectId` shape
and the `_SCHEMA` type strings are exact, because SDKs and mixed fleets read them. JSON
whitespace, header ordering and transport framing are not, and no SDK can observe them.

Where idiomatic Rust and a literal port disagree, idiomatic Rust wins, as long as nothing a client
can observe changes. Internal structure is free. The external surface is not.

That contract is why the tests look the way they do. Everything that touches upstream behavior is
checked against upstream rather than against someone's reading of it: the ECMAScript number
formatter against Node, bcrypt in both directions against the module parse-server loads, the
Parse/BSON transform against upstream's own `MongoTransform`, the `_SCHEMA` type strings against
what parse-server actually writes into MongoDB, and the acceptance gates against a running
parse-server.

## Quick start

The fastest way to see it answer a Parse SDK, with Docker and nothing else:

```
docker compose up
```

That builds parse-rust from the checkout, starts a MongoDB beside it, and serves
`http://127.0.0.1:27800/parse` with application id `demo` and master key `demo-master-key`. It is a
demo, not a deployment: the keys are public and the database has no authentication.
`tools/demo/check.sh` checks it from a fresh clone.

To run it yourself, it requires a stable Rust toolchain and a MongoDB you can write to. The test
suite runs against MongoDB 7 and 9; a single node is fine, no replica set needed.

Install the server:

```
cargo install parse-rust-cli      # installs a binary named `parse-rust`
```

Or embed it, which is the primary way this is meant to be used, since native Rust triggers and
adapter registration both require the deployment to compile its own binary:

```
cargo add parse-rust-server parse-rust-mongo
```

Either way it is configured the same:

```
PARSE_SERVER_APPLICATION_ID=your-app-id \
PARSE_SERVER_MASTER_KEY=a-long-random-secret \
PARSE_SERVER_DATABASE_URI=mongodb://127.0.0.1:27017/parse_rust_demo \
PORT=27800 \
parse-rust
```

From a clone rather than the registry, `cargo build --release` puts the same binary at
`./target/release/parse-rust`.

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
| `PARSE_SERVER_MASTER_KEY_IPS` | `127.0.0.1,::1` | comma-separated IP addresses or CIDR ranges allowed to use the master key |
| `PARSE_SERVER_DATABASE_URI` | `mongodb://127.0.0.1:27017/parse` | |
| `PORT` | `27800` | `0` binds an ephemeral port and prints it |
| `PARSE_SERVER_HOST` | `127.0.0.1` | upstream defaults to `0.0.0.0`; set that in a container |
| `PARSE_SERVER_MOUNT_PATH` | `/parse` | |
| `PARSE_SERVER_JAVASCRIPT_KEY` | unset | if set, non-master requests must present a client key |
| `PARSE_SERVER_REST_API_KEY` | unset | same |
| `PARSE_SERVER_SESSION_LENGTH` | `31536000` | seconds; one year, as upstream |
| `PARSE_SERVER_EXPIRE_INACTIVE_SESSIONS` | `true` | `false` issues sessions with no `expiresAt` |
| `PARSE_SERVER_ALLOW_CUSTOM_OBJECT_ID` | `false` | lets a client choose its own `objectId` on create |
| `PARSE_SERVER_ENABLE_SANITIZED_ERROR_RESPONSE` | `true` | whether a denial tells the client why |
| `PARSE_SERVER_PROTECTED_FIELDS` | `{"_User":{"*":["email"]}}` | JSON, as upstream's option takes |
| `PARSE_SERVER_PROTECTED_FIELDS_OWNER_EXEMPT` | `true` | an owner reads its own protected fields |
| `PARSE_SERVER_PROTECTED_FIELDS_SAVE_RESPONSE_EXEMPT` | `true` | a save response is not filtered |
| `PARSE_SERVER_REQUEST_COMPLEXITY_BATCH_REQUEST_LIMIT` | `-1` | unlimited; master and maintenance bypass it |
| `PARSE_SERVER_DATABASE_CREATE_INDEX_ROLE_NAME` | `true` | the unique index on `_Role.name` |
| `PARSE_SERVER_ALLOW_CLIENT_CLASS_CREATION` | `false` | whether a non-master caller may create a class |
| `PARSE_SERVER_ALLOW_ORIGIN` | `*` | comma-separated; an explicitly empty value allows no origin |
| `PARSE_SERVER_ALLOW_HEADERS` | unset | comma-separated, added to upstream's default list |
| `PARSE_SERVER_DEFAULT_LIMIT` | `100` | rows a find returns when it names no `limit` |
| `PARSE_SERVER_MAX_LIMIT` | unset | caps the rows a find returns |
| `PARSE_SERVER_DATABASE_ALLOW_PUBLIC_EXPLAIN` | `false` | whether `explain` works without the master key |
| `PARSE_SERVER_DATABASE_SCHEMA_CACHE_TTL` | unset | milliseconds before a cached schema is reloaded; unset or `0` never expires |
| `PARSE_SERVER_ACCOUNT_LOCKOUT` | unset | JSON, as upstream's option: `{"duration":5,"threshold":3}` |

The client keys are all-or-nothing, as upstream: configure none and none is required; configure
any one and every non-master request must present a matching key.

The master key is accepted only when the connection's peer address matches
`PARSE_SERVER_MASTER_KEY_IPS`. Forwarding headers do not change that address. A container or a
deployment behind a load balancer therefore has to list the address or CIDR range the server
actually sees, not the original client's address. The environment value is not whitespace-trimmed,
and an empty value is a startup error rather than "allow none", matching upstream.

An unparsable value is a startup failure rather than a fallback to the default. Several of these
are security defaults, and a typo in `PARSE_SERVER_EXPIRE_INACTIVE_SESSIONS` must not quietly
produce sessions that never expire.

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

Avoiding the preflight is only half of what a browser checks, so parse-rust also sends upstream's
CORS headers on every response, including error responses, and answers an `OPTIONS` preflight
directly. `PARSE_SERVER_ALLOW_ORIGIN` and `PARSE_SERVER_ALLOW_HEADERS` take comma-separated lists;
the defaults are `*` and the twelve headers a Parse SDK sends.

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

| Crate | | |
|---|---|---|
| [`parse-rust-server`](https://crates.io/crates/parse-rust-server) | [docs](https://docs.rs/parse-rust-server) | Library. Router, middleware, config. **What you depend on.** |
| [`parse-rust-cli`](https://crates.io/crates/parse-rust-cli) | [docs](https://docs.rs/parse-rust-cli) | Installs the `parse-rust` executable, and nothing else. |
| [`parse-rust-core`](https://crates.io/crates/parse-rust-core) | [docs](https://docs.rs/parse-rust-core) | Parse types, error codes, JSON encoding. No I/O. |
| [`parse-rust-schema`](https://crates.io/crates/parse-rust-schema) | [docs](https://docs.rs/parse-rust-schema) | Field types, inference, validation, the `_SCHEMA` storage format. |
| [`parse-rust-storage`](https://crates.io/crates/parse-rust-storage) | [docs](https://docs.rs/parse-rust-storage) | `StorageAdapter` trait and the query AST adapters lower. |
| [`parse-rust-mongo`](https://crates.io/crates/parse-rust-mongo) | [docs](https://docs.rs/parse-rust-mongo) | MongoDB adapter and the Parse/BSON transform. |
| [`parse-rust-rest`](https://crates.io/crates/parse-rust-rest) | [docs](https://docs.rs/parse-rust-rest) | The read and write pipelines. |
| [`parse-rust-auth`](https://crates.io/crates/parse-rust-auth) | [docs](https://docs.rs/parse-rust-auth) | Password hashing, `_Session`-backed sessions, role graph expansion. |

The project, the repository, this README and the executable are all **parse-rust**. Only the
Cargo package names carry a qualifier, because the normalized registry name `parse-rust` is
already occupied on crates.io by [an unrelated string-parsing
crate](https://crates.io/crates/parse_rust), and crates.io treats `parse-rust` and `parse_rust` as
one name.

**A library first, with a thin binary on top.** Native Rust triggers will require a deployment to
compile its own binary, and adapters are registered through a builder rather than resolved from a
module name, so the primary artifact is something you link against.

**The storage trait is shaped by two backends, not one.** It takes a query AST rather than a Mongo
query document, because handing a Mongo document to a SQL backend means writing a Mongo
interpreter in SQL. The rule: if a method can only be implemented sensibly for one backend, the
trait is wrong.

**Atomicity is part of that trait's contract.** If correctness depends on a predicate and a
mutation happening as one unit, that unit is one trait method. The method carries both the
precondition and the complete delta, and callers must not reconstruct either from state they read
earlier. No backend can restore atomicity after the interface has split it across calls. Most of
the schema-write defects fixed during 0.2.0 were fixed by changing the trait rather than the call
site, and the shape to watch for is a method that takes a whole schema and writes all of it: that
signature cannot express "change only this", so every caller of it is one interleaving away from
undoing another writer's change.

## Testing

```
tools/test.sh            # everything available on this machine
tools/test.sh --quick    # skip steps needing node, MongoDB or an upstream checkout
```

Steps that need more than a Rust toolchain skip with a stated reason rather than silently passing.

Several suites compare against a real parse-server checkout. They expect it as a sibling directory
(`../parse-server`), or wherever `PARSE_SERVER_ROOT` points, built at the revision in `PIN`. The
acceptance gates are:

- **Gate A** drives the whole flow through the unmodified `parse` npm SDK, including ACL round
  trips, cross-user read and write isolation, and rejection of invalid session tokens.
- **Gate B** points parse-rust *and* a real parse-server at the same database, writes with each,
  reads with the other, and compares the stored BSON types rather than just the values. Values
  alone would not catch the Int32-versus-Double rule, since both read back as the same JavaScript
  number.
- **Gate C** drives the authorization model through the same unmodified SDK against both servers
  and compares the answers: roles, class-level permissions, pointer permissions and protected
  fields.
- **Gate D** points both servers at one database and checks that neither rewrites the other's
  `_Session`, `_Role` or `_Join` schema, that a CLP block survives an ordinary write by either,
  and that a failed write leaves the same `_SCHEMA` state behind under both.
- **Gate E** boots parse-rust and parse-server at stock and configured settings, then exercises
  both from loopback and a second source address. It compares master-key IP filtering,
  CLP-declared default ACLs and the `_User` identity cases fixed in 0.2.1. Gate I extends it to
  the options and checks 0.3.0 adds.
- **Gate F** runs upstream's own spec files against parse-rust, block by block. Every request
  carries the block that sent it and parse-rust counts them; the suite runs again with no server,
  and the blocks that still pass must be exactly the ones declared not to need one; and the same
  patched suite must pass against parse-server.
- **Gate H** checks that `reconfigureServer` refuses, by name, any option parse-rust cannot honour,
  so a spec cannot pass by having its configuration silently ignored.
- **Gate J** benchmarks seven workloads against parse-server at three injected database latencies,
  after checking both servers give the same answer, and microbenchmarks the JSON and BSON
  transforms. It publishes distributions only, with no faster or slower verdict yet.
- **Gate K** brings the demo up twice from a fresh clone.

Each gate carries an assertion floor and fails if it runs fewer checks than it declares, so a gate
cannot quietly stop testing anything while still reporting green.

Gates B, C, D and E also run against a real parse-server, so a failure there means parse-rust
diverged rather than that an expectation was invented. Gate A's assertions hold against
parse-server too, but it is executed only against parse-rust.

What the gates do not do is check combinations. They walk stories, and the defects found late in
0.2.0 all came from composition: a server-imposed predicate meeting a client-supplied one, an
authorization decision keyed on the wrong one of two similar values, metadata written without the
state it describes. A hand-written runner does not think to write those, which is the argument for
running the upstream spec suite rather than for adding more gates.

## Reference implementation

Parse Server 9.10.3 is the target, pinned at the commit recorded in `PIN`. Claims about
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
