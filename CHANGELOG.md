# Changelog

Notable changes to parse-rust, newest first.

This project reimplements Parse Server, so an entry here answers two questions: what changed, and
what upstream behavior it matches. Wire-visible changes say so explicitly, because those are the
ones that can break a client. Deliberate differences from upstream are called out as such rather
than left for a reader to discover.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/). Versions are
[semantic](https://semver.org/), with the caveat that everything below 1.0.0 is subject to change:
the API this project promises to keep stable is Parse Server's, not its own Rust surface.

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
  (`RestWrite.js:116`, `:716-728`), so the create half was an omission rather than a decision: a
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
  same reason (`DatabaseController.js:1806-1811`, `RestQuery.js:121-131`).
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
  `POST /users`, `GET /users/me`, `POST /login`, `POST /logout`, `GET`/`POST /roles`,
  `GET`/`PUT`/`DELETE /roles/:objectId`, `GET /sessions`, `GET /sessions/me`,
  `GET`/`DELETE /sessions/:objectId`, `GET`/`POST /schemas`,
  `GET`/`POST`/`PUT`/`DELETE /schemas/:className`, `DELETE /purge/:className`. An unknown path
  answers 404. A known path with an unserved method answers 405, because the router matches the
  path before the method, with one exception: `POST` is registered almost everywhere as the
  JavaScript SDK's method-override transport, so a bare `POST` carrying no usable override reaches
  the dispatcher, finds no arm, and is reported as an unroutable method-and-path pair, which is a
  404. Upstream also serves `GET /users`, `GET /login`, `POST /sessions`,
  `PUT /sessions/:objectId` and `GET`/`PUT`/`DELETE /users/:objectId`, and none of those exist
  here, and upstream answers `/health` on any method where parse-rust serves `GET` and `POST`.
  Whole subsystems absent along with their routes: `/aggregate`, `/functions`, `/jobs`, `/files`,
  `/hooks`, `/push`, `/installations`, `/events`, `/config`, `/requestPasswordReset`,
  `/verificationEmailRequest`, `/loginAs`, `/upgradeToRevocableSession`, `/verifyPassword`,
  `/challenge`, `/scriptlog`, `/security`, `/cloud_code/jobs`, `/push_audiences`,
  `/validate_purchase`, `/graphql-config`, the pages routes under `/apps` and `/graphql`.
- **A client can save an existing `_User` but cannot create or delete one through `/classes`.**
  `user.save()` works: the SDK sends it as `PUT /classes/_User/:objectId`. An unauthenticated
  caller is refused before the ACL is consulted, `emailVerified` and `authData` are refused, a
  submitted `ACL` keeps the owner's entry, the password is hashed, the email format is checked, and
  username and email uniqueness is checked **case-insensitively**, which the `username_1` and
  `email_1` indexes do not do on their own. A password change revokes every session for that user
  and returns a replacement token, matching upstream. Create and delete on that route stay refused
  for an ordinary client, because both need stages of `transformUser` that do not exist yet;
  signup is `POST /users`, and a master or maintenance key reaches the row through
  `/classes/_User`.
  `/users/:objectId` still does not exist.
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
