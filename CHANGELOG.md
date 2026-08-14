# Changelog

Notable changes to parse-rust, newest first.

This project reimplements Parse Server, so an entry here answers two questions: what changed, and
what upstream behavior it matches. Wire-visible changes say so explicitly, because those are the
ones that can break a client. Deliberate differences from upstream are called out as such rather
than left for a reader to discover.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/). Versions are
[semantic](https://semver.org/), with the caveat that everything below 1.0.0 is subject to change:
the API this project promises to keep stable is Parse Server's, not its own Rust surface.

## 0.1.0

First public release. A proof of concept, not production software: it demonstrates that an
unmodified Parse SDK can drive parse-rust through a real signup, login, write, query and fetch,
and that the rows it writes are interchangeable with parse-server's on the same database.

### Added

- **Core types.** `ParseObject`, `Pointer`, `Date`, `Bytes`, `GeoPoint`, `File`, `ACL`, `Relation`
  and the update operations, with JSON encoding and decoding in both directions. Error codes are
  the upstream numeric codes, verified against `src/Error.js`.
- **ECMAScript number formatting.** Numbers serialize the way JavaScript's `Number::toString`
  does, checked against Node itself rather than against a reading of the specification.
- **Implicit schema.** A class is created by its first write, field types are inferred, and every
  later write is checked against them. `_SCHEMA` documents are byte-compatible with parse-server's.
- **MongoDB adapter** and the Parse/BSON transform, checked against upstream's own `MongoTransform`
  and against the BSON types parse-server actually stores.
- **The five `/classes` verbs**, with ACL enforcement on read, write and delete, and the response
  shapes upstream returns (`{objectId, createdAt}` on create, `{updatedAt}` on update, `{}` on
  delete).
- **Users.** `POST /users` signup with bcrypt hashing, `POST /login`, `GET /users/me`,
  `POST /logout`, and session tokens in upstream's `r:` format.
- **The JavaScript SDK transport.** Every SDK call arrives as a `POST` with a `text/plain` body
  carrying the method, credentials and query parameters. All of it is normalized before routing,
  as upstream does in `middlewares.js`.
- **Two acceptance gates.** Gate A drives the whole flow through the unmodified `parse` npm SDK.
  Gate B points parse-rust and a real parse-server at one database, writes with each, reads with
  the other, and compares stored BSON types rather than values.
- **A citation checker.** Every `File.js:LINE` citation in the repository is resolved against the
  pinned upstream commit in CI, so a citation cannot rot into looking verified when it is not.

### Names

The project, the repository and the executable are `parse-rust`. The Cargo packages carry a
qualifier, because crates.io normalizes `parse-rust` and `parse_rust` to one name and that name is
held by an unrelated string-parsing crate:

```
parse-rust-server   the embeddable server library, what you depend on
parse-rust-cli      installs the parse-rust executable
parse-rust-core     parse-rust-schema   parse-rust-storage
parse-rust-mongo    parse-rust-rest     parse-rust-auth
```

The name `parse-server` is deliberately left unclaimed on crates.io. This project is an unofficial
reimplementation and should not occupy the name of the thing it reimplements. The binary is
`parse-rust` rather than `parse-server` for a practical reason as well: it has to run beside a
stock parse-server on one machine for differential and benchmark runs, and two commands cannot
share a name.

### Deliberate differences from upstream

- **`objectId` generation is unbiased.** Upstream indexes a 62-character alphabet with
  `byte % 62`, which favors the first eight characters. The bias is not wire-visible, so this
  uses rejection sampling instead of reproducing a weak generator.
- **Writes to `/classes/_User` are refused for non-master callers.** Upstream permits them and
  makes them safe inside `RestWrite` regardless of route. parse-rust keeps the narrower client
  surface for now. Master and maintenance writes remain available and share signup's password
  hashing and owner-ACL preparation. Reads are unaffected.
- **The password hash is never raised under a user-facing name.** Upstream reattaches it as
  `password` and strips it later; here it keeps its internal name for its whole life, so no
  response path depends on remembering to remove it.
- **The server binds loopback by default.** Upstream's `PARSE_SERVER_HOST` defaults to `0.0.0.0`.
  The option is honored, but the default is local-only until this is production software.
- **`/serverInfo` advertises only what is implemented.** The `features` object keeps upstream's
  exact key set and nesting, which is what Parse Dashboard reads, but the booleans report reality
  instead of upstream's hardcoded `true`. Copying those literals would advertise a schema API,
  hooks, cloud jobs, a global config and a log API that have no routes here, and the dashboard
  would render controls that fail when pressed. Each flag flips as its subsystem lands. Upstream's
  own `spec/features.spec.js` asserts only that `features` is defined, so this turns no spec red.
- **The application id and master key are required at startup.** Upstream's documentation uses
  `myAppId` and `myMasterKey` as examples; defaulting to them would mean an unconfigured server
  answers to a master key printed in every Parse tutorial. The master key bypasses ACLs, CLPs and
  the class-security gate, so the server refuses to start instead.

### Known limitations

- Sessions are in memory. A restart logs everyone out, and two processes do not share them.
- Roles are not implemented, so a `role:` ACL entry matches nobody and therefore denies.
- Concurrent first writes to a new class or field are unsupported. The row commits before the
  schema is persisted, so two simultaneous first writes can disagree about a field's type. The
  fix is a conditional `_SCHEMA` update before the insert.
- Retried writes duplicate, because idempotency is not implemented. This matches upstream's
  default configuration, where the feature is off unless paths are configured.
- MongoDB only. The storage trait is shaped for a second backend, and Postgres is planned, but no
  Postgres implementation exists yet.
