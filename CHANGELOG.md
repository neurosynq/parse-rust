# Changelog

Notable changes to parse-rust, newest first.

This project reimplements Parse Server, so an entry here answers two questions: what changed, and
what upstream behavior it matches. Wire-visible changes say so explicitly, because those are the
ones that can break a client. Deliberate differences from upstream are called out as such rather
than left for a reader to discover.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/). Versions are
[semantic](https://semver.org/), with the caveat that everything below 1.0.0 is subject to change:
the API this project promises to keep stable is Parse Server's, not its own Rust surface.

## Unreleased (0.3.0)

The conformance milestone. parse-rust is now measured against parse-server's own test suite rather
than only against tests this project wrote for itself, and the reference is parse-server **9.10.3**,
a release, where 0.2.x was measured against a 9.10.1 alpha.

**Five authorization fixes apply to 0.2.0 and 0.2.1, and they are the reason to take this release
promptly.** A `_User` update now checks that the caller may write the target account before it
reads anything about it, as parse-server 9.10.3 does (GHSA-p49q-9w65-f9p7). `ACL` values on a
create are now lowered exactly as parse-server lowers them, so the stored permissions match
parse-server's for every shape a client can send. Credentials in a request body are read exactly
where parse-server reads them. A session token whose user no longer exists is refused with 209
`Invalid session token`, as parse-server refuses it. And a client delete is accepted only on a class
whose name a client could use.

### Added

- **The conformance harness**, `tools/conformance/run.mjs`. It runs upstream's spec files at the
  pin against parse-rust, block by block, and proves its subject three ways: every request carries
  the block that sent it and parse-rust counts them, the suite is run again with no server and the
  blocks that still pass must be exactly the ones declared client-only, and the identical patched
  suite must pass against parse-server built at the pin.
- **Geo queries**: `$nearSphere` with `$maxDistance` and its radian, mile and kilometre spellings,
  `$within` with `$box`, `$geoWithin` with `$polygon` or `$centerSphere`, and `$geoIntersects`, with
  upstream's validation messages. A count rewrites `$nearSphere` the way upstream does, inside
  `$or` too. A geo-near query on a GeoPoint field with no geo index builds a `2d` index and retries
  once, as upstream does.
- **`$text`** with `$search`, `$language`, `$caseSensitive` and `$diacriticSensitive`, building a
  `<field>_text` index and recording it in `_SCHEMA` the first time a field is searched. `$score`
  orders by relevance, most relevant first whichever sign it carries, and selecting `$score`
  returns it as `score`.
- **`explain`, `hint` and `comment`** on find, with `hint` and `comment` also carried by the count
  a find returns beside its results. `explain` requires the master key unless
  `databaseOptions.allowPublicExplain` is set, which defaults to false, so a query plan is never
  disclosed at the default.
- **`defaultLimit` and `maxLimit`.** `maxLimit` caps the resolved row count.
- **`accountLockout`**: the failed-login counter, the lock and its expiry, on the same
  `_failed_login_count` and `_account_lockout_expires_at` columns parse-server uses, so a lock set by
  either server in a mixed fleet is honored by the other. Login attempts on one account are handled
  one at a time within a server, so concurrent attempts are counted as if they arrived in sequence.
  `unlockOnPasswordReset` is accepted and has no effect, because there is no password reset yet.
- **`_Installation` validation.** `/classes/_Installation` has been reachable since 0.2.0 with none
  of upstream's write checks; 0.2.x listed installations among the absent subsystems, which was
  wrong. 0.3.0 adds string types for the three id fields, an id on every create from the body or
  the `X-Parse-Installation-Id` header, a `deviceType` on every create, lowercasing of a
  64-character `deviceToken` and of `installationId`, and upstream's update checks: an existing
  installation's `installationId` and `deviceType` cannot change, nor its `deviceToken` while
  neither side has an `installationId`, each refused with 136, and an update to a missing
  installation is `Object not found for update.`. A `deviceType` sent as an operation counts as
  present, as it does upstream. The deduplication that follows upstream is not implemented.
- **A schema cache.** Every request read `_SCHEMA` before its own query; it is now served from
  memory, as parse-server serves it. A schema change made through this server applies to the next
  request; a class another server created is loaded the first time a request names it, along with
  every other class; `GET /schemas` reloads. A change another server makes to a class already loaded waits for
  `databaseOptions.schemaCacheTtl` (milliseconds, `PARSE_SERVER_DATABASE_SCHEMA_CACHE_TTL`) or a
  restart, which is parse-server's behavior between its own nodes. Unset, the cache never expires,
  as upstream's does. `enableSchemaHooks` is refused at boot rather than accepted, because the
  change-stream invalidation it names is not implemented.
- A `test-harness` cargo feature, off by default, that adds the harness's control routes. A
  release build has neither.
- **A benchmark harness**, `parse-rust-bench`, which is not published, and a
  `bench-instrumentation` cargo feature, off by default, that attributes database time to each
  request. It times seven workloads against parse-server at three injected database latencies,
  after checking both servers give the same answer, and four microbenchmark families over frozen
  corpora. The report publishes distributions only, with no faster or slower verdict, until a noise
  floor exists to justify one.

### Changed

- **A signup applies the class's default ACL and the schema's defaults before hashing and the
  owner's ACL**, as upstream does: a `password` field can be required, a class default ACL is kept
  with the owner's entry added to it, and a missing required field is reported before a taken
  username.
- **`HEAD` is answered by a path's `GET` handler**, with no body, as Express answers it.
- **An empty `X-Parse-Installation-Id` is no installation id.**
- **`PARSE_SERVER_REVOKE_SESSION_ON_PASSWORD_RESET=false` is refused at boot**: a password change
  always revokes the user's other sessions.

- **A request's work runs to completion when its client disconnects**, as Express keeps running a
  request after its socket closes. A disconnect used to cancel it at its next step, part way through
  a write or a batch.
- **An empty `X-Parse-Session-Token` header is no session**, as upstream treats a falsy token,
  rather than 209.
- **`GET /users/me` with the master key and a session token** returns that token's user, as
  upstream's `handleMe` resolves the token itself.
- **A non-privileged `DELETE` of a `_User` row** answers 206 `Insufficient auth to delete user` for
  an anonymous caller and 206 `Permission denied` for another user, as upstream does, where it
  answered 119.
- **A session token whose user no longer exists is refused** with 209 `Invalid session token`.
- **`keys` naming a dotted path includes its parent**, as upstream forces the include, so
  `keys=author.name` returns `author` with only `name`.
- **A `where` is checked where upstream checks it.** A bad operand is refused after the CLP gate
  and not on a `limit=0` read; `$in`, `$nin` and `$all` with a non-array, and an unknown operator,
  are 107; `$exists` follows MongoDB's truthiness; a scalar or `null` `where` answers as upstream's
  does.
- **`order`** accepts `_created_at` and `_updated_at` as `createdAt` and `updatedAt`, and keeps the
  first position of a repeated key.
- **A `null` pointer** reads back as upstream's does: present as `null` after a create, absent after
  an update.
- **`userField:` rules** match a pointer inside an array.

- **Routing follows the effective method on every path.** A known path with a method it does not
  serve answers 404, as an Express router does, where it answered 405. A `POST` whose `_method`
  names a served method reaches it on every route, `/serverInfo` included, and one that names no
  valid method is a 404 rather than a `POST`. `/health` answers any method.
- **A write with no body is the empty object**, as body-parser's empty body is, so a body-less
  create, update, schema create, signup or batch sub-request runs rather than being refused. A body
  that is not JSON answers 400 `{error}`, body-parser's envelope; the message is this parser's.
- **A create answers with `Location`**, the new object's URL: the request's host and mount, then
  `/users/<id>` for a `_User` or `/classes/<className>/<id>`.
- **Schema field options are applied.** A create missing a field marked `required`, or sending it
  as `null`, `""` or a `Delete`, is 142 `<field> is required`, and so is an update that clears one.
  A field with a `defaultValue` that a create leaves out or deletes takes the default, which the
  response reports, as it reports a default ACL.
- **`/batch` validates before it refuses a transaction**, so a malformed transactional batch is
  reported as malformed, and sub-request paths are normalized as a POSIX join normalizes them, `.`
  and `..` included.
- **An unroutable `/batch` sub-request fails the whole batch** with 400 and 107
  `cannot route <method> <path>`, as upstream's router does; the sub-requests before it have run and
  the ones after it do not. The method is matched as sent, so a lower-case or missing method does
  not route, and neither does `/health`, which upstream mounts outside its router. Each was
  reported per item before. A sub-request method that is not a string fails the whole batch with a 500 before
  any of it runs, as upstream's does; 0.2.x ran it as a `GET`.
- **`/batch` sub-requests run concurrently, and so do the queries of an `include`**, as upstream
  runs them. A batch's results stay in request order. Two sub-requests touching the same object
  have no defined order between them, which is upstream's behavior and never was a guarantee. An
  include queries every path of one depth at once, and a deeper path after the depth above it.
- **`include` expands through an array of pointers**, as upstream's does: a pointer stored inside
  an array, which comes back from storage as a plain `{"__type":"Pointer"}` object, is expanded
  like a pointer field. It was returned as the raw pointer.
- **A request body over 20 MB is refused with `413 {"error":"request entity too large"}`**, which
  is Express's answer at upstream's default `maxUploadSize`. It reached its route as an empty body.
- **The MongoDB connection pool defaults to 100 connections**, the Node driver's default and so
  parse-server's, where the Rust driver's is 10. A `maxPoolSize` in the connection URI still wins.
- **`GET /login` is served**, and so is the SDK's `POST` with `_method: "GET"`. A login reads its
  credentials from the query string when the body has no username or email and the query string
  does, as upstream does, and reads nothing else from the body, so a stray key beside the
  credentials no longer fails it.
- **`GET /users`, and `GET`, `PUT` and `DELETE /users/:objectId`**, which upstream serves with the
  same handlers as `/classes/_User`. A caller fetching their own `_User` row, on either route, gets
  the session token they presented as its last key.
- **Checks on a write meet the client in upstream's order.** On a `_User` create the `role:`
  objectId guard precedes the objectId policy, and on signup the credential check precedes the
  restricted-field check. A `_User` update by anyone but the owner is authorized before its body is
  read, so a malformed body sent at somebody else's row answers 206, not the body's error. On an
  `_Installation` create the objectId policy precedes the installation checks.
- **An `ACL` in a response lists its principals in JavaScript key order**, an integer-like objectId
  ahead of `*`, as the object upstream builds it into does.
- **`limit` and `skip` are read as JavaScript reads them**: `Number()` over the decoded value, then
  the driver's truncation, as upstream reads them. `limit=0` answers an empty result
  without asking the database, and so without asking for `find` permission, which is what lets a
  class whose CLP grants only `count` be counted. The checks upstream runs before its find still
  apply: a `_Session` query with no session is 209, and a query or sort on a protected field is 119.
- **Read parameters sent in the body keep their JSON types.** The SDK sends a find as `POST` with
  `_method: "GET"` and its parameters in the body, and those were flattened into the query string
  and parsed as JSON a second time, so `{"comment":"123"}` became a number and was dropped, and
  `{"explain":"true"}` passed as `true` where upstream answers 102. A key in both the URL and the
  body now takes the URL's value, as upstream merges them.
- **`ACL` lowering follows parse-server's exactly.** An array's indices are principals, a flag is
  tested for truthiness rather than for `true`, integer-like principals are stored first in
  ascending order, a `null` entry is refused with a 500 and writes nothing, as is a `Batch`
  operation as an `ACL`.
- **`_User` signup refuses the `ACL` shapes parse-server refuses**, with its responses: a
  non-`Delete` operation with 400, code -1, `ACL must be a Parse ACL.`; an entry that cannot be built
  into a `Parse.ACL` with a 500. A truthy scalar `ACL` is 400, code -1, on signup and on update.
- **A non-owner `_User` update that is not found answers 206 `Permission denied`**, as upstream's
  does, not 101.
- **An empty or non-string `username` or `password` on a `_User` update** is refused with 200 or
  201, as 9.10.3 refuses it, master key included. A non-string `password` was 111.
- **The create and update CLP gates run before the `addField` gate and the required-column check**,
  as 9.10.3 orders them, so a write failing two checks names the operation.
- **A `File` whose `name` is not a non-empty string is refused at any depth** with 111 `This is not
  a valid File`, as 9.10.3 refuses it.
- **An update response lists the operation results first and `updatedAt` last**, upstream's order.
- **An `include` replaces each pointer where it stands** rather than moving it to the end of its
  object, so an included object's keys keep upstream's order.
- **A storage error on a find answers `{"code":1,"error":"An internal server error occurred"}`**,
  upstream's body for that path. An explain, and a query the adapter refuses while building it,
  such as a `$geoWithin` point with latitude 100, keep the bare
  `{"code":1,"message":"Internal server error."}`, as upstream's do.
- **An owner's `_User` update checks `username` and `password` before the class-level `update`
  permission**, as 9.10.3 orders them, so an empty username under a CLP that closes `update` is 200,
  not 119.
- **`keys`, `excludeKeys`, `include` and `order` are JavaScript's `String()` of the decoded value**,
  as upstream reads them, from the URL or the body. An array is its elements joined with commas,
  so `keys=["n","text"]` selects both fields where it selected neither, and `order=["-n"]` sorts
  where it was 105. `keys=null` is no projection.
- **A read runs its checks in upstream's order.** Parameter names and the `where` JSON are checked
  before class security, and the explain gate before the query is read. An unknown top-level
  operator is 105 `Invalid key name: $foo`, raised after the CLP gate, where it was 102 before it. A
  class that does not exist is refused, when client class creation is off, before the sort and CLP
  checks, and is otherwise still queried, so an invalid operand is refused on it too. The count
  beside a find validates the find's sort, and a negative `skip` is refused after the query is
  built. An explain with `limit=0` answers `[]` before the CLP gate, the `include` pass and the
  check of the explain value, which is made after the CLP gate.
- **Geo and `$text` operands are read as JavaScript reads them.** A `null` operand whose member
  upstream reads is a bare 500, `$maxDistanceInMiles` and `$maxDistanceInKilometers` coerce a
  string, and a `$centerSphere` distance that coerces to a non-negative number reaches the database
  as sent.

- **Credentials in a request body are read exactly where parse-server reads them**, and `_method`
  overrides the method of a `POST` only, in any case.

### Deliberate differences

- Protected fields are enforced across more of the read path.
- A client delete or read is accepted only on a class whose name a client could use.
- A malformed query is refused as one: `$or`, `$and` and `$nor` must be non-empty arrays of objects
  (102, with a message naming the problem), a lone `$options` is 102, and `$exists` given an object
  or an array that is not a Parse value is 107 on every field. parse-server answers several of
  these with a 500, a `Permission denied` or a widened result.
- The rows an `include` grafts into one response are capped at 128 MiB of JSON; past it the read
  answers the generic 500, which parse-server answers only when its response no longer fits in a
  JavaScript string.
- A create sending `null` for a field with a `defaultValue` stores the `null` (201), or answers 142
  `<field> is required` when the field is also required. parse-server answers a 500 for both,
  because its required-field step reads `.__op` off the `null` (`RestWrite.js:424-425`).
- The on-demand geo index is built only for a field declared as a GeoPoint. A geo query on any
  other field fails.
- A request naming a class the schema cache lacks and `_SCHEMA` does not have keeps the cache.
  parse-server reloads every class on any miss; parse-rust reloads them when the class exists,
  which means another server changed the schema, and otherwise answers from the cache it has.
- `databaseOptions.enableSchemaHooks: true` is refused at boot. parse-server accepts it and
  invalidates its schema cache from a change stream, which parse-rust does not implement;
  `schemaCacheTtl` bounds staleness instead.
- A `_User` signup whose `ACL` parse-server refuses is refused before the insert, in both of
  upstream's branches. Without an `email` on the body, parse-server inserts the row and then
  refuses, leaving the username taken; parse-rust leaves nothing.
- A truthy scalar `ACL` on `_User` is always 400, where parse-server answers 400 or 500 depending
  on whether the body carries an `email`, and 500 on an update.
- `objectId: {"__op":"Delete"}` under `allowCustomObjectId` stays refused with 107. parse-server
  accepts it and stores the row under an id the client is never told.

### Known limitations

- `$select`, `$dontSelect`, `$inQuery`, `$notInQuery`, `$containedBy`,
  `includeAll` and `redirectClassNameForKey` are still refused by name, and the conformance run
  reports the blocks that need them as failures.
- Cloud Code, triggers, LiveQuery, files, push, GraphQL and Postgres are unchanged from 0.2.0.

## 0.2.1

A security patch. Three authorization decisions were broader in 0.2.0 than they are in
parse-server, all at stock server configuration, meaning none needed an operator to change an
option away from its default.

**What a deployment running 0.2.0 is exposed to.** The master key is accepted from any source
address, where a stock parse-server accepts it only from the machine it runs on; anyone who obtains
the key can use it remotely. A user signed up with an `ACL` of `null`, `false`, `0`, `""` or
`{"__op":"Delete"}` is created world-readable rather than private. And objects created in a class
whose schema declares a `classLevelPermissions.ACL` are written with no ACL at all, so a class
configured as private is world-readable.

The second of those needs no configuration of any kind and applies to `_User`, so it is the one to
weigh first if you are deciding how quickly to take this.

**Two further `_User` failures are fixed here and are denial rather than disclosure**, so they do
not change the urgency above but they do change what a running deployment may already have suffered:
a `_User` update carrying an `ACL` that is an operation, an array or a tagged value cleared the
owner's permissions, which locks the owner out of their own account and could be done by any
principal permitted to write that row. And a create carrying a truthy non-string `objectId` with an
inferable schema type was given a generated one instead of being refused. The remaining array and
`Delete`-operation exceptions are named under "Known limitations" rather than hidden inside either
claim.

No new routes and no new vocabulary. There is one source-compatibility break for embedders, under
"Changed". Take it.

### Fixed

- **`masterKeyIps` is enforced, at upstream's default of `['127.0.0.1', '::1']`**
  (`Options/Definitions.js:402-406`, `middlewares.js:452`). The option was unimplemented, and its
  default is a control rather than a convenience, so an absent implementation was an open one. A
  master key presented from an address outside the list is refused with upstream's bare 403
  `unauthorized` and is **not** demoted to an ordinary client request, matching upstream, which
  throws rather than falling through. The empty list means the key cannot be used at all, including
  from the server itself. `maintenanceKeyIps` is enforced the same way and carries the same default.
  - **The address is the connection's, never a header's.** Upstream's `getClientIp` is `req.ip`
    with Express's `trust proxy` left off, so `X-Forwarded-For` is ignored; an allowlist that reads
    a client-supplied header is not an allowlist. A deployment behind a load balancer therefore
    sees every request as coming from the balancer and has to widen the option. Trusted-proxy
    configuration does not exist yet, and until it does that is the direction to fail in.
  - **Address matching is two mechanisms.** Five entries are allow-all literals scoped to one
    family: `::/0`, `::` and `::0` admit every IPv6 peer and no IPv4 peer, and `0.0.0.0/0` and
    `0.0.0.0` do the reverse. An IPv4-mapped address such as `::ffff:127.0.0.1` counts as IPv6 for
    those, so `0.0.0.0/0` does **not** admit it. Every other entry is matched in one 128-bit space
    where a mapped address is its IPv4 form, so the ordinary rule `127.0.0.1` does admit
    `::ffff:127.0.0.1`. Both halves are re-derived from upstream's `checkIp` at the pin on every
    test run rather than transcribed, because the wrapper carries the first mechanism and the
    block list underneath it carries only the second.
  - **New:** `PARSE_SERVER_MASTER_KEY_IPS`, comma-separated, addresses or CIDR ranges, with
    upstream's strictness: not trimmed, and an empty value is an error rather than a silent
    deny-all, because upstream's `Config.validateIps` refuses both. The one place this is stricter
    is an out-of-range prefix such as `127.0.0.1/999`, which upstream accepts at boot and then
    throws on the first master-key request; here it stops the server and names the entry.
  - **No `PARSE_SERVER_MAINTENANCE_KEY_IPS`, and that is a parse-rust CLI limitation rather than a
    gap upstream.** The pin defines both `PARSE_SERVER_MAINTENANCE_KEY` and
    `PARSE_SERVER_MAINTENANCE_KEY_IPS` (`Options/Definitions.js:387`, `:392`). This binary exposes
    neither, because master and maintenance are still one scope internally, so shipping the key
    through the CLI would advertise an authority the server only partly distinguishes. Both are
    reachable through `ServerConfig`.
  - **Maintenance is tested before master**, matching `resolveKeyAuth`. The order was reversed and
    was unobservable until the two keys had separate allowlists: with both headers present and the
    allowlists disagreeing, whichever key is tested first decides both the resulting authority and
    whether the request is refused at all.
- **A `_User` whose `ACL` is not a principal map is no longer created world-readable.** Upstream
  runs two tests on it, `if (!ACL) { ACL = {}; }` and then `ACL[objectId] = {read, write}`
  (`RestWrite.js:1815-1825`), and both were read as "is it an object" here:
  - `null`, `false`, `0` and `""` are **falsy**, so they mean "no ACL" and get the owner-only ACL
    an absent one gets.
  - An op envelope, an array and a tagged value are all **JavaScript objects**, so they receive the
    owner too. For an op envelope and a tagged value the owner is then the only entry carrying a
    permission, so the row comes back owner-only. An array whose elements carry permissions is the
    exception and is a recorded gap: `[{"read":true}]` grants principal `"0"` upstream, because an
    index is a property name, and parse-rust collapses it to owner-only.

  **Five of those seven produced a public row and two did not**, and the distinction is worth
  stating rather than rounding off. The four falsy values and `{"__op":"Delete"}` left no permission
  columns at all, which is public: an anonymous read of such a user answered 200 here and 404
  upstream. The array and the tagged value left two **empty** columns, which is master-only, so both
  servers answered 404 and the defect there was the missing owner rather than a disclosure. A
  non-`Delete` operation behaved like the array. All seven representative shapes now preserve the
  owner and match upstream's visibility. A permission-bearing array is the
  narrower exception described above and under "Known limitations". A truthy **scalar** is still
  left as sent and is master-only; upstream throws a `TypeError` and answers a bare 500 there, so
  there is no answer worth reproducing.
- **A `_User` update can no longer strip the owner's own access.** `force_owner_into_acl` re-adds
  the owner entry for every non-privileged update carrying a truthy `ACL` (`RestWrite.js:1729-1738`)
  and it handled a principal map and `{"__op":"Delete"}` and nothing else. Every other truthy shape
  reached the lowering, which cleared both permission columns, and a `_User` with empty permissions
  is a row its owner can no longer read, write or log in with. **Any principal permitted to write a
  `_User` could disable that account.** Measured at the pin with `{"__op":"Increment","amount":1}`
  on `PUT /classes/_User/:id`: both servers answer 200, upstream keeps the owner entry and the
  caller's existing session still resolves, and parse-rust stored `{}` and the same session then
  answered 209 `INVALID_SESSION_TOKEN`. A **falsy** `ACL` on an update is still left alone, which is
  upstream's `this.data.ACL &&` guard and leaves the stored columns untouched. Permission-bearing
  arrays keep the owner now but still lose their numeric-index principals, as recorded below.
- **A truthy non-string `objectId` with an inferable schema type on a `_User` create is refused
  rather than replaced.** Upstream's substitution test is `if (!this.data.objectId)`
  (`RestWrite.js:489-491`), so a truthy id survives to the type check and, for numbers, booleans,
  arrays, tagged values, ordinary objects and typed operations, answers `INCORRECT_TYPE`. Reading
  "not a string" as "absent" generated one instead: measured at the pin with
  `allowCustomObjectId` enabled and a body of `{"objectId": 123}`, upstream answered 400 code 111
  and wrote no row through either `POST /users` or `POST /classes/_User`, and parse-rust answered
  201 with an id the client never asked for, persisted the user and issued a session for it. The
  same change fixes an **empty-string** `objectId`, which was previously taken as the id itself,
  creating a `_User` whose objectId was `""` and whose every ACL entry named nothing. A `Delete`
  operation has no inferred type upstream and is the recorded exception below.
- **An `ACL` carrying an operation no longer produces a public row on any class.** The same root
  cause, one layer down: `flatten_for_create` removes a `Delete` op from the body, so the `ACL` key
  was gone before the permission columns were computed and none were written. Upstream keeps the op
  object and writes two **empty** arrays, which is master-only. Measured at the pin on an ordinary
  class: an anonymous read of the created object answered 200 here and 404 upstream.
- **A CLP-declared default ACL is applied on create** (`RestWrite.js:438-455`). The setting was
  accepted by `POST /schemas`, stored, and echoed back by `GET /schemas`, and nothing ever read it,
  so every object in the class was created with no `_rperm` or `_wperm` columns and an absent
  `_rperm` is public. The class said private and the data was world-readable, which is worse than
  not supporting the feature. `currentUser` resolves to the caller's objectId and the literal key is
  removed, so the stored ACL names a principal that exists. The default applies on **create and
  never on update**, matching upstream's `!this.query` guard: stamping it on an update would revert
  an ACL a client changed on purpose. A declaration of exactly `{"*": {"read": true, "write": true}}`
  is skipped, by upstream's key-order-sensitive `JSON.stringify` comparison rather than a structural
  one.
- **The create response carries the ACL the server generated.** It is the only way a client learns
  what permissions its object was given, and on a private class it cannot read the row back to find
  out. Upstream marks the field server-changed and returns it (`RestWrite.js:454`), including the
  empty `{}` an anonymous create produces once `currentUser` has nobody to resolve to.

### Changed

**This is a patch release with a source-compatibility break for embedders, decided rather than
discovered.** Cargo resolves 0.2.1 as compatible with 0.2.0 and will upgrade into it unasked, so
both of the following are stated here rather than left to a build failure.

- **`parse_rust_server::auth::resolve` keeps its 0.2.0 signature and is deprecated.** The real
  entry point is `resolve_with_peer`, which takes the connection's address. The two-argument form
  still compiles and **fails closed**: with no address to check `masterKeyIps` against it refuses
  every master and maintenance key, and leaves every other request alone. Preserving 0.2.0's
  behavior instead was not an option, because 0.2.0's behavior here is the defect.
- **`ServerConfig` is now `#[non_exhaustive]`.** This release adds two public fields, which already
  breaks any `ServerConfig { .. }` literal outside the crate; the attribute makes that break happen
  once rather than again on every future option. Construction is `ServerConfig::new` followed by
  field assignment, which the attribute still permits.
- **`parse_rust_server::serve` serves with connect info.** An embedder that mounts `router` into
  its own axum app without `into_make_service_with_connect_info` has no peer address to filter on,
  so the two privileged keys are refused there. Every other route is unaffected.

### Known limitations

- **A CLP-declared default ACL is not applied to `_User` creation.** Signup stamps the new user's
  own owner ACL before the pipeline sees the body, so the class default is suppressed by it.
  Upstream stamps the default first and then adds the owner, so its result is the class default
  plus the owner and parse-rust's is the owner alone. **Narrower than upstream in every case, never
  broader**: a role named in a `_User` default ACL does not gain read access here where it would
  upstream. Blast radius: a `_User` class whose schema declares a `classLevelPermissions.ACL`
  grants less here than upstream, and a mixed fleet writing `_User` rows through both servers gets
  two different ACL shapes for the same signup.
- **JavaScript's full ACL enumeration is not yet reproduced.** Upstream lowers an ACL with a
  `for...in`, while parse-rust's lowering understands only a principal map.
  - A permission-bearing array such as `[{"read":true}]` grants principal `"0"` upstream because
    an array index is an enumerable property name. parse-rust drops that principal. On an ordinary
    class or a CLP-declared default ACL the result is two empty permission columns; on `_User`
    create and update the owner is retained but the numeric principal is still omitted. The result
    is narrower than upstream, and a mixed fleet writes different ACL shapes.
  - Integer-like keys have JavaScript's index ordering upstream rather than ordinary insertion
    ordering. A principal map containing `"2"` before `"1"`, or `currentUser` resolving to a custom
    objectId such as `"0"`, is enumerated with the integer keys first upstream and in input or
    insertion order here. The permission set is the same, but generated ACL responses and the
    order of `_rperm` and `_wperm` differ.
- **`objectId: {"__op":"Delete"}` is refused where upstream accepts it when
  `allowCustomObjectId` is enabled.** Upstream's type inference returns no type for `Delete` and
  skips the field check, answering 201 with the operation object as `objectId`; parse-rust refuses
  it with 400 code 107. Other truthy non-string shapes with an inferred type are covered by the
  fix above. This malformed-but-observable case is scoped for 0.3.0 rather than included in the
  blanket 0.2.1 claim.
- **Two `ACL` shapes on `POST /users` are accepted where upstream refuses the request.** An
  operation envelope such as `{"__op":"Increment","amount":1}`, and a truthy scalar such as
  `"nonsense"`, `123` or `true`. Upstream answers 400 `ACL must be a Parse ACL.` for the first, and
  for the second answers 400 with an `email` on the body and **500 without one**. parse-rust answers
  201 for both.
  - **The row is private either way**, which is what this release fixed: the operation case gets
    the owner-only ACL, and the scalar case gets two empty permission columns. Nothing is disclosed.
  - **The state is not, and upstream's own answer depends on the body.** With an `email` present
    upstream validates before the database write, so no row exists and the username stays free,
    while parse-rust persists the user and consumes the username, and a retry answers 202
    `USERNAME_TAKEN` where upstream answers 201. **Without an `email` upstream inserts the row and
    throws afterwards**, so both servers leave a row and both consume the username, and only the
    status differs. In the scalar case the session parse-rust issues cannot read its own user,
    because the row is master-only, so the account is created and unusable.
  - Both are `_User` only; an ordinary class matches upstream. Both are scoped for 0.3.0, where
    the scalar case additionally has to choose between reproducing upstream's email-dependent
    400/500 split and refusing cleanly with a documented 4xx. Continuing to answer 201 is not one
    of the options.
- **No trusted-proxy configuration**, so `masterKeyIps` behind a load balancer sees the balancer.
  Named above, and scoped out of this release deliberately.
- Everything under 0.2.0's known limitations still applies, with one correction to that list: it
  named `maintenanceKeyIps` as the reason the maintenance key was not exposed by the binary and did
  not say that the **master** key was subject to no IP filter either. Both are filtered now.

## 0.2.0

The authorization milestone. 0.1.0 could talk to a Parse client; 0.2.0 can be pointed at a Parse
database. Roles resolve, class-level permissions are evaluated, pointer permissions narrow queries,
protected fields are stripped, and the sessions and roles it writes are the rows parse-server reads
from the same database.

Still not production software. Single-node, MongoDB only, no triggers, files, LiveQuery, push or
GraphQL. The known limitations below name what is missing behind the routes that do exist, and the
route list in them is exhaustive. Treat any Parse Server endpoint not named there as absent.

### Added

- **CORS.** `Access-Control-Allow-Origin`, `-Allow-Methods`, `-Allow-Headers` and
  `-Expose-Headers` on every response including error responses, and an `OPTIONS` preflight
  answered directly rather than routed. There were no CORS headers at all before, which is a total
  outage for any browser-hosted client and easy to miss from a server log: the JavaScript SDK's
  `text/plain` `POST` avoids the *preflight*, but a browser still discards the response of a
  request it cannot match an origin against, so every call failed while the server reported 200.
  Anything that does preflight, parse-dashboard included, got a 405 instead. `allowOrigin` and
  `allowHeaders` are configurable, with upstream's defaults and upstream's origin-echoing rule.
- **Roles.** `_Role` with its `users` and `roles` relations, the five `/roles` verbs, and role
  graph expansion including transitive membership. A cycle in the graph terminates and resolves
  both names rather than hanging, matching upstream, which cuts cycles instead of rejecting them.
  A `role:` entry in an ACL now matches; in 0.1.0 it matched nobody and therefore denied.
- **Class-level permissions**, both stages. The gate that throws, over the seven operations
  (`find`, `count`, `get`, `create`, `update`, `delete`, `addField`), and the filter that narrows the query
  (`pointerFields`, `readUserFields`, `writeUserFields`). CLP is **default-open**: an absent
  operation entry means unrestricted, matching `testPermissions`. Failing an operation's
  `requiresAuthentication` entity, which is a key inside a permission object rather than an
  operation of its own, returns `OBJECT_NOT_FOUND` (101) and not `OPERATION_FORBIDDEN`, which is
  upstream's deliberate existence hiding.
- **`protectedFields`**, computed by intersecting every applicable entity group, so more applicable
  groups means fewer protected fields. Querying or ordering by a protected field is
  `OPERATION_FORBIDDEN` rather than a filtered result; without that a client can binary-search the
  value it cannot read.
- **Persisted sessions.** `_Session` rows with upstream's columns, `r:` plus 32 hex characters,
  `expiresAt`, `createdWith`, and duplicate destruction per user and installation. Sessions survive
  a restart and are visible to a parse-server on the same database. The in-memory map is gone.
- **Relations.** `_Join:<key>:<class>` tables, `AddRelation` and `RemoveRelation` including inside
  a `Batch`, `$relatedTo`, and constraints on a `Relation`-typed field. A caller who cannot read
  the owning object gets an empty result rather than an error, so a relation is not a membership
  oracle.
- **Atomic operations.** `Increment`, `Add`, `AddUnique`, `Remove` and `Delete` are applied rather
  than stored as literal objects. The update response echoes back the post-write value of the five
  keys upstream's `_sanitizeDatabaseResult` allow-lists, `Increment`, `SetOnInsert`, `Add`,
  `AddUnique` and `Remove`; a `Delete` and a plain set both answer with `updatedAt` alone.
- **The schema API.** `GET`, `POST`, `PUT` and `DELETE` on `/schemas`, plus `DELETE /purge`, all
  master-key only. `/serverInfo` advertises the schema capabilities because the routes now exist.
- **`/batch`**, with per-operation results and upstream's error shape. `transaction: true` is
  refused rather than accepted and run without one.
- **`/sessions`**: `me`, list, get and delete. A non-master read is narrowed to the caller's own
  sessions.
- **Query vocabulary:** `$or`, `$and`, `$nor`, `$regex` with `$options`, `$all`, `excludeKeys`, and
  `include` with dotted paths. An included pointer is a full query against the target class with
  the caller's own permissions, not a graft.
- **Two acceptance gates.** Gate C drives the authorization model through the unmodified `parse`
  npm SDK against both servers. Gate D points both servers at one database and checks that neither
  rewrites the other's `_Session` or `_Role` schema, that `_Join:users:_Role` collects documents
  from both while neither writes it a `_SCHEMA` row, and that a CLP block survives an ordinary
  write by either.

### Fixed

- **A schema `defaultValue` is stored exactly as sent, and a query operand is compared as sent.**
  Both used to go through the ordinary decoder, which recognizes a `__type` envelope and rebuilds
  it: an ISO instant with an offset came back in UTC, unpadded base64 came back padded, and any key
  the envelope does not declare was dropped. Stored, that means a parse-server node reads back
  something the client never wrote. Compared, it means something worse: the predicate is not the one
  asked for, and `$in` carrying a pointer nested in an object with an unknown key matched a row
  upstream does not return. Operand handling now follows upstream's shape exactly, including its
  asymmetry, an unknown key *on* an atom is discarded because upstream reconstructs the atom, while
  one *inside* a plain object is compared, because upstream leaves plain objects alone.


- **`allowClientClassCreation` was not implemented, so the server behaved as though it were on.**
  Upstream's option defaults to `false`, so an absent implementation is not a missing feature but a
  security default flipped open: a caller holding only the app id and client key could bring classes
  into existence without limit, each with a `_SCHEMA` row and a collection on a database
  parse-server nodes also read, and each with no CLP block and therefore open. Implemented with
  upstream's default, gated before any `_SCHEMA` write, exempting master, maintenance and the
  classes Parse defines itself, and readable from `PARSE_SERVER_ALLOW_CLIENT_CLASS_CREATION`.
- **A truthy non-object `ACL` on a create produced a world-open row.** Nothing type-checks `ACL` on
  either side, deliberately, so `{"ACL":"x"}` reaches the lowering step from any client. The test
  upstream applies there is falsiness, not "is it an object": anything truthy still writes `_rperm`
  and `_wperm` as empty arrays, which is a master-only row, and only a falsy value writes neither.
  parse-rust wrote neither for any non-object, and an absent column is public. The update path had
  always applied the falsy test, so the two write paths disagreed on the same body. The reachable
  case was `_Role`, whose required-column check tests truthiness and stops there: a non-object `ACL`
  satisfied it and produced a world-writable role any caller could add itself to.
- **Seven internal columns failed the whole read.** An unrecognized `_`-prefixed column is
  `INVALID_QUERY`, and the pass-through list was shorter than upstream's. parse-rust writes none of
  the missing ones, but a parse-server on the same database writes them whenever password reset,
  email verification, account lockout or a password policy is on, and those `_User` rows then failed
  every read here: login, `GET /users/me`, and any query matching them. The list now tracks
  upstream's, plus the legacy `_expiresAt` spelling.
- **`emailVerified` was accepted on signup.** Upstream refuses it on any `_User` write through
  `checkRestrictedFields`, which sits in the chain both create and update run
  (`RestWrite.js:119`, `:779-791`), so the create half was an omission rather than a decision: a
  client could mark its own address verified at signup. Both paths now refuse it. `authData` is
  refused alongside it, which is a deliberate difference rather than restored parity, and is
  recorded as one below: upstream accepts `authData` on signup and validates it through the auth
  adapter, which is the third-party login path.
- **`include` is bounded, because the obvious implementation is a single-request denial of
  service.** `include` is new in this release, so nothing shipped with the unbounded form, but the
  first version written here had it: expanding every prefix of a dotted path is quadratic in the
  component count, each expanded path becomes at least one further query, and a 16 KB parameter
  allocated 2.7 GB. The depth and path count are now bounded and refused by name rather than
  truncated, and the deduplication no longer allocates: the same input is refused in well under a
  millisecond.
- **Logging in with an email address did not work.** Upstream matches a bare identifier against
  `username` **or** `email`, which is what `Parse.User.logIn(emailAddress, password)` relies on in
  every SDK; matching `username` alone answered `Invalid username/password.` for a correct email and
  password, and an `email` key sent on its own was not read at all. `/login` also collapsed three
  distinct refusals into `USERNAME_MISSING`, so a client that omitted its password and one that sent
  a non-string password were both told the username was missing. Each now answers its own code.
- **The schema API substituted two error codes.** `type <T> needs a class name` and
  `field <name> cannot be added` are 135 and 136 upstream, and the spec suite asserts on those
  numbers directly. parse-rust answered 111 and 105 on a comment claiming neither number had an
  `ErrorCode` variant; both have had one since the codes were enumerated.
- **Three query constructs answered the wrong thing silently.** `$all` full of `$regex` atoms, which
  is what `containsAllStartingWith` sends, was lowered as a subdocument rather than compiled, so it
  matched nothing and returned 200. A bare objectId string against a Pointer field was not prefixed
  with its target class, so `{"author": {"$in": ["abc123"]}}` matched nothing. A nested `GeoPoint`,
  `Polygon` or `File` was converted to its top-level storage form rather than kept as the envelope
  upstream stores, which a mixed fleet reads as disagreement about the column's contents. An
  `equalTo` against an `Array`-typed field now becomes upstream's single-element `$all`, which is
  what makes a Pointer comparable against an array of pointers instead of erroring.
- **CLP validation skipped anything that was not a plain object.** Upstream enumerates an operation's
  entries with a `for...in`, which visits arrays and tagged values too, so `{"find": ["*"]}` is
  refused there and was accepted here. The consequential shape was a tagged value: it passed
  validation, stored, and then read back as **deny-all**, locking the class with nothing reported at
  the time of the write that locked it.
- **The schema API reported indexes a class does not have.** `indexes` was rendered as `{}` when a
  class had none, where all three upstream renderers omit the key and the spec suite compares the
  whole object. A create also seeded a phantom `_id_` into `_metadata.indexes`; measured against a
  running parse-server, a create records the submitted block alone and only an update onto a class
  with no recorded block seeds `_id_`. `{"type": "ACL"}` was accepted as a field type and answered
  200 for a field that never came into existence. A `targetClass` change reported 255 rather than
  falling through to the type mismatch upstream reports. `DELETE /schemas` on a class whose
  `_SCHEMA` row is missing returned 200 and did nothing, so a dashboard could not drop it.
- **bcrypt ran on a runtime worker.** Hashing at cost 10 is tens of milliseconds of pure CPU with no
  await point in it, and both entry points are reachable without credentials, so as many concurrent
  requests as there are workers stopped the runtime polling anything at all, including `/health`.
  Both calls now run on the blocking pool. This is not a substitute for the rate limiting that is
  still absent; it removes the case where one caller stops the process without needing volume.

- **The concurrent first-write schema race**, documented as a 0.1.0 limitation. Field types are now
  reserved with a conditional update on the `_SCHEMA` document before the row is inserted, so a
  losing writer fails the condition rather than overwriting the winner's type.
- **Gate B was measuring parse-server against itself.** `directAccess` defaults to `true`, and
  parse-server then replaces the SDK's REST controller with an in-process router, so every SDK call
  in that process reached upstream regardless of the configured server URL. One direction of the
  0.1.0 data-fidelity gate was a second upstream write. The gate still passes once genuinely
  bidirectional, so the fidelity claim survives; it had not been measured.
- **Denial messages disclosed more than upstream does.** `enableSanitizedErrorResponse` shipped in
  0.1.0 with upstream's `true` default but reached only the master-key gate, and could not be set
  from the environment, so a stock parse-server answered `Permission denied` where parse-rust
  returned the class name, the field name and the reason. Now applied at every denial and readable
  from `PARSE_SERVER_ENABLE_SANITIZED_ERROR_RESPONSE`. Two adjacent paths leaked the same way and
  are fixed with it: the raw MongoDB duplicate-key message carried the database name and the
  colliding value, and the generic 500 envelope carried the internal detail under the wrong key.
- **`_Role.name` had no unique index.** Two roles could share a name, and an ACL entry `role:X`
  then granted the members of both. Now created at startup as `name_1`, behind `createIndexRoleName`.
- **`include` bypassed two authorization checks**, because both lived in the `/classes` route
  handler and a nested read never touches one. The `_Session` narrowing was the exploitable half:
  a pointer to another user's session row, plus `include`, returned that session's live token.
  Both checks moved into the read pipeline, where upstream has them (`RestQuery.js:54`,
  `:116-134`), so every nested read inherits them.
- **A malformed CLP operation entry failed open.** Upstream denies on any truthy value, so
  `{"find": true}` and `{"find": []}` are deny-all there; parse-rust read them as absent, which is
  unrestricted. `PUT /schemas` refuses the scalar form and, like upstream, accepts neither an
  array nor a tagged object since this release, so the remaining route in is a block written
  straight into `_SCHEMA`, which has to be read the way parse-server reads it.
- **A client could name an internal column in a `where` clause.** `{"_hashed_password": {"$regex":
  "^a"}}` reached storage, which recovers a bcrypt hash one character at a time. The internal-field
  allow-lists are now enforced; `_hashed_password` is queryable by nobody, including master.
- **`_id` is stringified rather than decoded**, matching upstream. Documents parse-server creates
  without an explicit id carry a BSON ObjectId, which every join collection in a real database is
  full of, and decoding it as an ordinary value rejected the document.
- **A server-imposed constraint could collide with a client's and fail the query.** Pointer
  permissions and the `_Session` narrowing appended their constraint beside the client's, so an
  client naming the same field the server was about to constrain, its own session's `user` or the
  pointer field a `pointerFields` entry names, got `INVALID_QUERY` `conflicting constraints` where
  upstream returns the row. Both now nest under `$and`, which is what upstream does and for the
  same reason (`DatabaseController.js:1808-1811`, `RestQuery.js:121-131`).
- **`enforceRoleSecurity` saw the wrong method.** The read method was derived from the query shape
  rather than taken from the route, so a `find` whose `where` pinned one objectId, and every
  `include` regardless of size, were checked as a `get`. Clients may `get` an installation and may
  not `find` one, so either form returned `_Installation` rows a page at a time. The method and the
  CLP operation are now separate values, which is how upstream carries them.
- **Schema index requests created metadata and no index.** `POST` and `PUT /schemas` stored the
  `indexes` block verbatim without validating the fields or building anything, so `_SCHEMA` claimed
  an index that did not exist. A parse-server node on the same database reads that claim and does
  not build it either, which leaves the class unindexed with both servers believing otherwise.
  A parse-server node rewrites `_metadata.indexes` from Mongo's real catalogue at startup, so the
  false claim is erased at its next restart rather than believed indefinitely. Indexes are now built
  first and recorded from what was built, deletions drop the real index, and an index on an unknown
  field is refused.
- **`allowCustomObjectId` was modelled but not enforced.** At its default of `false` a create
  carrying `objectId` or `id` was honored, where upstream refuses both with `INVALID_KEY_NAME`.
  Enforced on every create route including signup, and with the option on, an empty `objectId` is
  refused with `MISSING_OBJECT_ID` as upstream does.
- **An update to a missing class had a body-dependent side effect.** An empty update left no schema
  row and an update naming a new field created one as a side effect of reserving the field.
  Upstream has one answer for both, because `enforceClassExists` runs before any field is looked
  at: the class is created and the update then answers `OBJECT_NOT_FOUND`.
- **The schema API's writes were not atomic.** `POST /schemas` read the class list and then
  upserted, so two concurrent creates for one class both passed the read and both wrote, and the
  loser's fields and CLP replaced the winner's. `PUT /schemas` folded field additions into a cloned
  schema and wrote the whole field set with one unconditional `$set`, so two concurrent additions of
  one field with different types both succeeded and the later one silently redefined it. Creation is
  now an insert whose duplicate-key answer is where "already exists" comes from, and each addition
  goes through the same conditional reservation an ordinary write uses.
- **A write refused for a bad field name left no schema row.** The class creation sat behind field
  validation, so the schema side effect of a failed write depended on which way the body was
  invalid. `enforceClassExists` runs before any field is inspected upstream, which Gate D now
  checks against a real parse-server on both write paths.
- **An existing field's options could not be cleared and were not validated.** The update plan
  recorded options only when non-empty, so resubmitting `{"type":"String"}` for a field stored as
  `{"type":"String","required":true}` did nothing, and a `required` field could never be made
  optional again. Option validation was also gated on the field being new, so a `defaultValue`
  whose type disagreed with the stored field type was stored rather than refused. Upstream reaches
  `enforceFieldExists` for every field a body *sets*, not only the new ones, and applies exactly one option rule there, the
  `defaultValue` type check; the rest sit behind its `existingFieldNames` guard.
- **`_metadata.fields_options` could be written for a field that no longer exists**, because the
  update carried no `{field: {$exists: true}}` guard. A field deleted between a request's read and
  its write left options behind for a column that is not there.
- **A `PUT /schemas` response was assembled rather than re-read.** A reservation that loses a race
  writes nothing, so a response built from the request could report options the database does not
  have. Rendered from a reload, which is what upstream answers with.
- **The CLP was written after the indexes.** A body carrying both a valid CLP and an index on an
  unknown field is refused by both servers, and upstream has already written the CLP by then.
  Reordered to match, so the half that survives a partly-invalid request is the permissions rather
  than the index.
- **`PUT /schemas` still wrote the whole schema.** Excluding the newly reserved fields was not
  enough: the write still carried every pre-existing field and the whole `_metadata.fields_options`
  block, so a stale snapshot could `$set` a concurrently deleted field back into `_SCHEMA`, and two
  concurrent additions each carrying options could erase each other's while keeping their types.
  Every write on that path is now a delta: a field's type and options go in one conditional update,
  an existing field's options go by path, and indexes and CLP are written only when the request
  carried them. The schema API reaches storage through those operations rather than through a
  whole-schema upsert.
- **An invalid class name was written into `_SCHEMA` before being refused.** `POST /classes/1Bad`
  answered 103 and left a `1Bad` row behind, on a database parse-server also reads. Upstream
  answers `INVALID_JSON` `schema class name does not revalidate` and writes nothing, which is the
  fixed string its terminal catch substitutes for the detailed 103 the schema route gives.
- **A non-string custom `objectId` was silently replaced.** With `allowCustomObjectId` on,
  `{"objectId": 123}` created a row under a generated id and reported success; upstream keeps the
  value and answers `INCORRECT_TYPE`, having created the class first, which the first version of
  this fix got backwards by checking the objectId before the class existed. The same guard tests
  truthiness rather than presence, so with the option on a falsy id is `MISSING_OBJECT_ID`, and at
  the default it is replaced by a generated one rather than refused.
- **The `role:`-prefixed `_User` objectId guard covered only signup.** It is on `ClassesRouter`
  upstream, which `UsersRouter` extends, so it covers `POST /classes/_User` too.
- **A malformed `indexes` block was silently ignored**, so a client that asked for indexes and got
  a 200 had no way to learn none were built.
- **`SetOnInsert` was refused as an unknown operation.** It is now decoded, flattened, lowered to
  `$setOnInsert` and echoed back like the other result-bearing operations, and refused on the REST
  surface where upstream refuses it, so a client cannot get a write past parse-rust that
  parse-server would have rejected. Both servers answer the generic
  `{"code":1,"message":"Internal server error."}` envelope, because upstream's refusal is a bare
  string throw rather than a `Parse.Error`.

### Deliberate differences from upstream

- A `count` denied by a **pointer permission** returns `0`. Upstream's deny branch returns a
  literal `[]` for every operation except `get`, which throws `OBJECT_NOT_FOUND`, so a denied count
  answers `{"count": []}` there. A count denied by the CLP itself is 119 under both servers.
- `include=*`, dotted update keys, `$inQuery`, `$notInQuery`, `$select`, `$dontSelect`, geo and
  `$text` are all implemented upstream and unimplemented here, and each is refused rather than
  dropped from the query: a query operator by name, a dotted update key as an invalid field name.
  A dropped constraint broadens a result set, which is an authorization failure rather than a
  missing feature.
- Non-master writes to `_Session`, and non-master creates and deletes of `_User`, through
  `/classes` are refused. All are fail-closed over a write stage parse-rust does not yet have; the
  `_Session` one would otherwise be account takeover. A non-master `_User` **update** is allowed,
  because it is what `user.save()` sends.
- `authData` is refused on a client `_User` write, create and update alike, rather than stored.
  Upstream hands it to an auth adapter that decides whether the credential is real; with no adapter
  host, storing it unvalidated would let a client write a third-party identity that a later login
  could match on. `emailVerified` is refused on both alongside it, which is upstream's own
  restriction and applies to both there too.
- A non-string `password` on a `_User` update is refused with `INCORRECT_TYPE` rather than reaching
  the hashing library with a value it cannot hash. Signup answers `PASSWORD_MISSING` under both
  servers.
- **A refused `PUT /schemas` applies none of itself.** A request that both deletes a field and
  retargets an existing Pointer or Relation is refused whole. Upstream performs the deletions
  first and discovers the target mismatch afterwards, so the column is gone from `_SCHEMA` and from
  every row while the request still answers `111 schema mismatch`. Same rule as the CLP-ordering
  entry above: a request parse-rust refuses leaves no durable state on a database parse-server also
  reads, and matching upstream here would mean making a *failed* schema update destructive. Cost,
  and it is a real one: in a mixed fleet the identical failed request leaves different state
  depending on which node served it, and the difference is a deleted field.
- **The `include` limits are fixed and apply to every caller.** A maximum depth of 20 and a maximum
  of 500 expanded paths, refused by name. Upstream has `requestComplexity.includeDepth` and
  `includeCount` and **defaults both to `-1`, meaning unbounded**, exempting master and maintenance.
  A 16 KB `include` parameter expanded into gigabytes of allocation before this was bounded, and a
  configurable limit whose default is unbounded is the same defect with a knob on it. Blast radius:
  a request over either limit is refused here and served upstream, and master gets no exemption.
- **An unparsable option fails startup rather than becoming `false`.** Upstream's `booleanParser`
  accepts `true`, `'true'` and `'1'` and returns **false for everything else**, and its number
  parser is `parseInt`, which reads `30d` as `30`. parse-rust accepts `true`/`1` and `false`/`0`,
  requires a whole integer, and refuses anything else. Every option these parse is a security
  default, so reading `treu` as "off" or `30d` as thirty seconds is the failure worth refusing.
- `/batch` withholds the detail of a non-Parse error, the same as parse-rust does outside a batch.
  The response shape stays upstream's, meaning still no `code` key; only the message is generic.
- The CLP gate on a create runs before any `_SCHEMA` write, which is a deliberate ordering
  difference from upstream and the one place the write pipeline is not a straight port. Upstream
  validates the schema first, so a create it then refuses can leave a newly inferred field behind;
  here a refused create writes nothing, on the principle that a refused request leaves no durable
  state on a database parse-server also reads. The client-visible answer is the same denial either
  way; the difference shows only through `GET /schemas`.
- A top-level `indexes` value that is not an object is refused with `INVALID_QUERY`. Upstream has
  no such check, so the outcome falls out of JavaScript coercion and lands on three different
  answers depending on the JSON type, one of them a 500. Blast radius: a client sending
  `"indexes": []` where it meant `{}` gets a refusal here and a success upstream.
- An index key value that is neither a number nor a string is refused with `INVALID_QUERY`.
  Upstream validates the index's field names and hands the values straight to the driver, which
  puts a driver message on the wire. No such index is valid in MongoDB either, so the request
  fails under both servers and only the code and message differ.
- The per-field options write is issued without upstream's `upsert: true`, which is meaningless
  beside the `{field: {$exists: true}}` filter it is paired with and reachable only by a field
  deleted mid-write. The guard itself is reproduced, which is the part that matters: options are
  never written for a field that no longer exists.
- **A `null` operand in a constraint on a `Relation` field is refused with `INVALID_JSON`.**
  Upstream reads `objectId` off each operand of `$in`, `$nin` and `$ne` without a guard, and `null`
  is the one value JavaScript will not box, so it raises an uncaught `TypeError` and the request
  answers a generic 500. Every other unusable operand is harmless there: a number or an object
  without an `objectId` yields `undefined` and contributes no id. Reported upstream as
  parse-community/parse-server#10637. Skipping the element instead would be worse than either
  answer: a dropped element of a `$nin` leaves an empty exclusion list, which excludes nobody, so
  the query would return every otherwise-readable row where upstream returns none. Blast radius: a
  client sending a null relation operand gets a 107 here and a 500 upstream, and no query answers
  with more rows than it was asked for.
- **A malformed `__type` envelope in a query operand is refused rather than converted.** Each
  coder's validity test is the tag alone, with no check on the payload, so upstream converts
  whatever it is given: `{"__type":"Date"}` becomes an invalid date, `{"__type":"GeoPoint"}` becomes
  a pair of nulls, `{"__type":"Pointer","className":"C"}` compares against the literal string
  `C$undefined`, `{"__type":"File"}` compares as null, and `{"__type":"Bytes"}` raises a type error
  in the driver rather than a Parse error. Each is a comparison against a value the client never
  wrote, or a 500. parse-rust declines to recognize the envelope, which leaves it an ordinary object
  and lands on upstream's own `INVALID_JSON` for a non-atom operand. Blast radius: narrowing in
  every case, a refusal here where upstream answers with a garbage match.

Each entry is a deliberate opt-out with a stated reason, not an unfinished edge. Differences found
after release are tracked as defects instead.

### Known limitations

- **The routes, exhaustively, by method.** `GET`/`POST /health`, `GET /serverInfo`,
  `POST /batch`, `GET`/`POST /classes/:className`, `GET`/`PUT`/`DELETE /classes/:className/:objectId`,
  `GET`/`POST /users`, `GET /users/me`, `GET`/`PUT`/`DELETE /users/:objectId`,
  `GET`/`POST /login`, `POST /logout`, `GET`/`POST /roles`,
  `GET`/`PUT`/`DELETE /roles/:objectId`, `GET /sessions`, `GET /sessions/me`,
  `GET`/`DELETE /sessions/:objectId`, `GET`/`POST /schemas`,
  `GET`/`POST`/`PUT`/`DELETE /schemas/:className`, `DELETE /purge/:className`. An unknown path
  answers 404. A known path with an unserved method answers 405, because the router matches the
  path before the method, with one exception: `POST` is registered almost everywhere as the
  JavaScript SDK's method-override transport, so a bare `POST` carrying no usable override reaches
  the dispatcher, finds no arm, and is reported as an unroutable method-and-path pair, which is a
  404. Upstream also serves `POST /sessions` and `PUT /sessions/:objectId`, and neither exists
  here, and upstream answers `/health` on any method where parse-rust serves `GET` and `POST`.
  Whole subsystems absent along with their routes: `/aggregate`, `/functions`, `/jobs`, `/files`,
  `/hooks`, `/push`, `/installations`, `/events`, `/config`, `/requestPasswordReset`,
  `/verificationEmailRequest`, `/loginAs`, `/upgradeToRevocableSession`, `/verifyPassword`,
  `/challenge`, `/scriptlog`, `/security`, `/cloud_code/jobs`, `/push_audiences`,
  `/validate_purchase`, `/graphql-config`, the pages routes under `/apps` and `/graphql`.
- **A client can save an existing `_User` but cannot create or delete one through `/classes` or
  `/users/:objectId`.** `user.save()` works: the SDK sends it as `PUT /classes/_User/:objectId`. An unauthenticated
  caller is refused before the ACL is consulted, `emailVerified` and `authData` are refused, a
  submitted `ACL` keeps the owner's entry, the password is hashed, the email format is checked, and
  username and email uniqueness is checked **case-insensitively**, which the `username_1` and
  `email_1` indexes do not do on their own. A password change revokes every session for that user
  and returns a replacement token, matching upstream. Create and delete on that route stay refused
  for an ordinary client, because both need stages of `transformUser` that do not exist yet;
  signup is `POST /users`, and a master or maintenance key reaches the row through
  `/classes/_User` or `/users/:objectId`.
- **The maintenance key is not exposed by the binary, deliberately.** `ServerConfig` honours one, so
  an embedder can set it, but no environment variable enables it and the README no longer advertises
  it. Upstream restricts the key with `maintenanceKeyIps`, **defaulting to `['127.0.0.1', '::1']`**,
  which is localhost only. parse-rust has no IP filter, so shipping the option would mean a
  credential that bypasses `protectedFields` and the `_`-prefix sweep, reachable from any address,
  where upstream reaches it from one. The option lands with its IP policy or not at all.
- **Master and maintenance are one scope internally, and they are not the same authority.** The ACL
  scope treats them alike, because they apply the same ACL treatment: none. At least one decision
  reads them differently, and upstream is explicit about it: `validateClientClassCreation` exempts
  both on a write and master alone on a read. That case is corrected by a separate flag; the general
  conflation remains, so any *other* decision that should distinguish the two currently does not.
  The maintenance key is not otherwise a documented feature of this release.
- **Known parity gaps, found by review and deferred rather than chosen.** Each is wire-visible and
  each is a defect rather than a decision, so none is listed above as a deliberate difference. They
  are recorded here because an undocumented difference is worse than a documented one, and because
  every one of them was found by running the two servers side by side rather than by reading:
  - `$all` classifies any regex operand where upstream classifies specifically the `^\Q...\E`
    form its `containsAllStartingWith` generates (`MongoTransform.js:143-150`). So upstream accepts
    an ordinary regex alongside a plain value and rejects a lone `^ba`, and parse-rust does the
    opposite.
  - `/login` reads credentials from the body only. Upstream falls back to the query string when the
    body carries neither `username` nor `email` (`UsersRouter.js:74-79`), so `POST /login?username=
    ...&password=...` with an empty body logs in there and answers 200 `USERNAME_MISSING` here.
  - The CORS layer wraps the whole service rather than the mounted API, so `OPTIONS` on a path no
    route claims answers 200 with CORS headers where upstream answers 404.
  - Signup checks the restricted-field rules before the missing-credential rules, so a body with
    neither username nor password *and* an `emailVerified` key reports the restricted field where
    upstream reports the missing credential.
  - The absent-class check runs after the `where` is parsed, so a malformed constraint against a
    class that does not exist reports the constraint (102) where upstream reports the class (119).
  - `keys` and `excludeKeys` are not folded into `include`, so an included object carries every
    field the caller may read rather than only the projected ones (`RestQuery.js:146-160`). ACLs,
    CLP and `protectedFields` still apply to it; this is a projection difference, not an access one.
  - `HEAD` is not handled consistently across routes.
- No schema cache and no role cache. Every request reloads every schema, and role expansion issues
  one query per level of the graph. Both are correct and slow, and both are deferred deliberately:
  a cache decides what a caller may see, so its staleness window is an authorization decision
  rather than a tuning knob.
- No conformance harness. Zero spec files from the upstream suite run green against parse-rust,
  because nothing runs them against it yet. Every claim here rests on hand-written differential
  runners that check what someone thought to check. This is the largest gap in the project and
  the next milestone should not ship without closing it.
- No idempotency, no session renewal, no password reset, no email verification, no auth adapters,
  no MFA, no account lockout, no password policy.
- MongoDB only.
- The gates check stories, not combinations. Every fix in this release's second round came from
  reading the pinned source rather than from a failing gate, and the pattern in them is
  composition: a server-imposed predicate meeting a client-supplied one, an authorization decision
  keyed on the wrong one of two values, metadata written without the state it describes. Those are
  the cases a hand-written runner does not think to write, which is the argument for the
  conformance harness rather than for more gates.

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
