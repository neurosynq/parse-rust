/*
 * Gate D of the 0.2.0 milestone: sessions and roles are shared state, on one database.
 *
 * This is the gate that earns the words "can be pointed at a Parse database". Gate C only shows
 * that parse-rust enforces an authorization model; this shows that the `_Session` rows, the
 * `_Role` graph and the `_SCHEMA` documents it writes are the ones a parse-server node reads from
 * the same collection, and the reverse. Without it, 0.2.0 demonstrates only that parse-rust agrees
 * with itself.
 *
 * It boots a real parse-server against whatever database parse-rust is using and drives both
 * through their REST APIs with the unmodified SDK. Case 3 goes underneath the API and compares the
 * stored `_SCHEMA` documents through the Mongo driver, the way Gate B compares stored BSON types
 * rather than REST values: a schema round trip that normalizes a CLP block is invisible over HTTP
 * and changes what every other node in the fleet enforces.
 *
 * Every assertion holds against parse-server in both roles, so a failure means parse-rust wrote
 * something upstream does not read, or read something upstream does not write.
 *
 * Usage:
 *   node tools/spec/shared-auth-state.mjs <parse-rust-url> <mongo-uri> [appId] [masterKey]
 */

import { createRequire } from 'node:module';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const require = createRequire(import.meta.url);
// Resolve the parse-server checkout relative to this repository rather than to a home directory,
// so the default works for anyone with the two repos side by side. Override with
// PARSE_SERVER_ROOT when it lives elsewhere.
// **Resolved to an absolute path, including the override.** `require` resolves a relative
// specifier against *this file's* directory, not the working directory, so a relative
// `PARSE_SERVER_ROOT` such as `../parse-server-pinned` was looked for under `tools/spec/` and
// failed with a module-not-found naming a path nobody wrote. That matters now that a pinned
// worktree is the way to run these against the declared release target.
const PS_ROOT = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)), '..', '..',
  process.env.PARSE_SERVER_ROOT || '../parse-server',
);
const { ParseServer } = require(`${PS_ROOT}/lib/index.js`);
const Parse = require(`${PS_ROOT}/node_modules/parse/node`);
const { MongoClient } = require(`${PS_ROOT}/node_modules/mongodb`);

const [, , RUST_URL, MONGO_URI, APP_ID = 'test', MASTER_KEY = 'test'] = process.argv;
if (!RUST_URL || !MONGO_URI) {
  console.error('usage: node tools/spec/shared-auth-state.mjs <parse-rust-url> <mongo-uri> [appId] [masterKey]');
  process.exit(2);
}

// A floor, because a check that can pass by finding nothing will. A case that throws early, or a
// block deleted in a refactor, drops the run below this and fails as a harness error rather than
// reporting a green suite that exercised a fraction of the surface.
const ASSERTION_FLOOR = 75;

const PASSWORD = 'correct horse battery staple';
const TAG = `${process.pid}x${Date.now().toString(36)}`;
const MASTER = { useMasterKey: true };
const as = token => ({ sessionToken: token });

let passed = 0;
const failures = [];

function J(v) {
  return JSON.stringify(v);
}
function check(name, cond, detail = '') {
  if (cond) {
    passed++;
  } else {
    failures.push(`${name}${detail ? `: ${detail}` : ''}`);
  }
}
function eq(name, actual, expected) {
  check(name, actual === expected, `expected ${J(expected)}, got ${J(actual)}`);
}
async function outcome(fn) {
  try {
    return { ok: true, value: await fn() };
  } catch (e) {
    return { ok: false, code: e?.code, message: e?.message };
  }
}

/** Everything one server does happens with `Parse.serverURL` pointed at it and nowhere else. */
async function on(url, fn) {
  Parse.serverURL = url;
  return fn();
}

async function signUp(url, name) {
  return on(url, async () => {
    const user = new Parse.User();
    user.set('username', `${name}_${TAG}`);
    user.set('password', PASSWORD);
    await user.signUp();
    return { id: user.id, token: user.getSessionToken(), username: user.get('username') };
  });
}

async function createRole(url, name, userIds) {
  return on(url, async () => {
    const acl = new Parse.ACL();
    acl.setPublicReadAccess(true);
    const role = new Parse.Role(`${name}_${TAG}`, acl);
    for (const id of userIds) {
      role.getUsers().add(Parse.User.createWithoutData(id));
    }
    await role.save(null, MASTER);
    return role;
  });
}

async function saveWithACL(url, className, values, buildACL) {
  return on(url, async () => {
    const object = new Parse.Object(className);
    object.set(values);
    const acl = new Parse.ACL();
    buildACL(acl);
    object.setACL(acl);
    await object.save(null, MASTER);
    return object;
  });
}

async function setCLP(url, className, clp) {
  return on(url, async () => {
    const schema = new Parse.Schema(className);
    schema.setCLP(clp);
    const exists = await outcome(() => new Parse.Schema(className).get());
    return exists.ok ? schema.update() : schema.save();
  });
}

async function main() {
  Parse.initialize(APP_ID, undefined, MASTER_KEY);
  // In Node the SDK does not persist a current user, so every call below carries the token it was
  // given and nothing else. Stated rather than assumed.
  Parse.User.disableUnsafeCurrentUser();

  // `directAccess` defaults to `true` (`Options/Definitions.js:191-196`) and makes `startApp`
  // replace the SDK's REST controller with an in-process router (`ParseServer.ts:370-372`). With
  // it on, every SDK call in this process reaches upstream whatever `Parse.serverURL` says, and a
  // gate about two servers sharing a database quietly becomes one server talking to itself.
  const upstream = await ParseServer.startApp({
    appId: APP_ID,
    masterKey: MASTER_KEY,
    databaseURI: MONGO_URI,
    serverURL: 'http://127.0.0.1/parse',
    mountPath: '/parse',
    port: 0,
    silent: true,
    allowClientClassCreation: true,
    directAccess: false,
  });
  const UP_URL = `http://127.0.0.1:${upstream.server.address().port}/parse`;

  const client = await MongoClient.connect(MONGO_URI);
  const db = client.db(new URL(MONGO_URI).pathname.replace(/^\//, ''));
  const schemaDoc = id => db.collection('_SCHEMA').findOne({ _id: id });

  // ---------------------------------------------------------------------------------------------
  // Case 1: a session token issued by one server is accepted by the other
  // ---------------------------------------------------------------------------------------------

  const fromRust = await signUp(RUST_URL, 'd1_rust');
  check('parse-rust issues a session token', typeof fromRust.token === 'string' && fromRust.token.startsWith('r:'), J(fromRust.token));

  const rustTokenAtUpstream = await on(UP_URL, () => Parse.User.me(fromRust.token));
  eq('parse-server accepts a parse-rust session token', rustTokenAtUpstream.id, fromRust.id);
  eq('and resolves it to the same user', rustTokenAtUpstream.get('username'), fromRust.username);

  const fromUpstream = await signUp(UP_URL, 'd1_upstream');
  check('parse-server issues a session token', typeof fromUpstream.token === 'string' && fromUpstream.token.startsWith('r:'), J(fromUpstream.token));

  const upstreamTokenAtRust = await on(RUST_URL, () => Parse.User.me(fromUpstream.token));
  eq('parse-rust accepts a parse-server session token', upstreamTokenAtRust.id, fromUpstream.id);
  eq('and resolves it to the same user', upstreamTokenAtRust.get('username'), fromUpstream.username);

  // A token neither server issued is refused by both, so the two assertions above are acceptance
  // rather than a server that accepts anything.
  for (const [who, url] of [['parse-rust', RUST_URL], ['parse-server', UP_URL]]) {
    const bogus = await on(url, () => outcome(() => Parse.User.me('r:00000000000000000000000000000000')));
    check(`${who} refuses an unknown session token`, bogus.ok === false, `it returned ${J(bogus.value)}`);
    eq(`${who} refuses it as INVALID_SESSION_TOKEN`, bogus.code, Parse.Error.INVALID_SESSION_TOKEN);
  }

  // The row is in Mongo rather than in a process, which is the other half of the claim.
  const sessionRow = await db.collection('_Session').findOne({ _session_token: fromRust.token });
  check('a parse-rust session is a row in _Session', !!sessionRow);
  eq('the session points at its user', sessionRow?._p_user, `_User$${fromRust.id}`);

  // ---------------------------------------------------------------------------------------------
  // Case 2: a role graph written by one server governs reads on the other
  // ---------------------------------------------------------------------------------------------

  const Shared = `SharedRole_${TAG}`;

  // parse-server writes the role and the row; parse-rust has to resolve both.
  const upMember = await signUp(UP_URL, 'd2_up_member');
  const upOutsider = await signUp(UP_URL, 'd2_up_outsider');
  await createRole(UP_URL, 'WrittenByUpstream', [upMember.id]);
  await saveWithACL(UP_URL, Shared, { title: 'public' }, acl => acl.setPublicReadAccess(true));
  const upRow = await saveWithACL(UP_URL, Shared, { title: 'upstream role row' }, acl =>
    acl.setRoleReadAccess(`WrittenByUpstream_${TAG}`, true));

  const seenByRust = await on(RUST_URL, () => new Parse.Query(Shared).get(upRow.id, as(upMember.token)));
  eq('parse-rust resolves a role parse-server wrote', seenByRust.get('title'), 'upstream role row');
  const outsiderAtRust = await on(RUST_URL, () => new Parse.Query(Shared).find(as(upOutsider.token)));
  eq('a non-member still reads the public row on parse-rust', outsiderAtRust.length, 1);
  eq('and it is the public one', outsiderAtRust[0]?.get('title'), 'public');

  // And the reverse.
  const rustMember = await signUp(RUST_URL, 'd2_rust_member');
  const rustOutsider = await signUp(RUST_URL, 'd2_rust_outsider');
  await createRole(RUST_URL, 'WrittenByRust', [rustMember.id]);
  const rustRow = await saveWithACL(RUST_URL, Shared, { title: 'rust role row' }, acl =>
    acl.setRoleReadAccess(`WrittenByRust_${TAG}`, true));

  const seenByUpstream = await on(UP_URL, () => new Parse.Query(Shared).get(rustRow.id, as(rustMember.token)));
  eq('parse-server resolves a role parse-rust wrote', seenByUpstream.get('title'), 'rust role row');
  const outsiderAtUpstream = await on(UP_URL, () => new Parse.Query(Shared).find(as(rustOutsider.token)));
  eq('a non-member still reads the public row on parse-server', outsiderAtUpstream.length, 1);
  eq('and it is the public one', outsiderAtUpstream[0]?.get('title'), 'public');

  // ---------------------------------------------------------------------------------------------
  // Case 3: neither server rewrites the other's `_SCHEMA`
  //
  // This is the case that catches the real bug, and it cannot be seen over HTTP.
  // ---------------------------------------------------------------------------------------------

  // A `Relation` field has no column: the join documents live in `_Join:<key>:<class>`, which has
  // no `_SCHEMA` row at all (`DatabaseController.js:418-420` builds that schema as a literal and
  // never registers it). A row there is a class every parse-server node in the fleet starts
  // seeing, so the assertion is that the collection has documents and the schema entry does not
  // exist. Without the first half, "no row" would pass on a database where no role has members.
  const joinCount = await db.collection(`_Join:users:_Role`).countDocuments();
  check('both servers populated _Join:users:_Role', joinCount >= 2, `${joinCount} join document(s)`);
  const joinSchema = await schemaDoc('_Join:users:_Role');
  check('_Join:users:_Role has no _SCHEMA row', joinSchema === null,
    `found ${J(joinSchema)}`);

  // The `_Role` field types are the contract between the two servers. Relations are stored as
  // `relation<Target>` strings and synthesized back on read; a differently spelled one is a class
  // the other node cannot follow.
  const roleSchema = await schemaDoc('_Role');
  check('_Role has a _SCHEMA row', !!roleSchema);
  eq('_Role.users is relation<_User>', roleSchema?.users, 'relation<_User>');
  eq('_Role.roles is relation<_Role>', roleSchema?.roles, 'relation<_Role>');
  eq('_Role.name is a string', roleSchema?.name, 'string');

  const sessionSchema = await schemaDoc('_Session');
  check('_Session has a _SCHEMA row', !!sessionSchema);
  eq('_Session.sessionToken is a string', sessionSchema?.sessionToken, 'string');
  eq('_Session.user is a pointer to _User', sessionSchema?.user, '*_User');
  eq('_Session.expiresAt is a date', sessionSchema?.expiresAt, 'date');

  // Now make each server do more `_Role` and `_Session` work and prove neither rewrote the other's
  // document. Both orders, because "A does not disturb B" and "B does not disturb A" are two
  // different claims and only one of them is about the server you happen to test second.
  const before = { _Role: J(roleSchema), _Session: J(sessionSchema) };

  const upWriter = await signUp(UP_URL, 'd3_up');
  await createRole(UP_URL, 'D3Upstream', [upWriter.id]);
  eq('parse-server left _Role alone', J(await schemaDoc('_Role')), before._Role);
  eq('parse-server left _Session alone', J(await schemaDoc('_Session')), before._Session);

  const rustWriter = await signUp(RUST_URL, 'd3_rust');
  await createRole(RUST_URL, 'D3Rust', [rustWriter.id]);
  eq('parse-rust left _Role alone', J(await schemaDoc('_Role')), before._Role);
  eq('parse-rust left _Session alone', J(await schemaDoc('_Session')), before._Session);

  // The CLP block, which is the regression this gate exists for. A naive `upsert_schema` rewrites
  // the whole `_SCHEMA` document and takes `_metadata.class_permissions` with it, so a class the
  // other server locked down reverts to `defaultCLPS` and becomes fully public on every node.
  // Compared byte for byte rather than semantically: an unset CLP and a CLP that sets only `find`
  // are two different documents, and a round trip that normalizes one into the other is exactly
  // the failure being tested for.
  const CLP = {
    find: { requiresAuthentication: true },
    get: { requiresAuthentication: true },
    count: { requiresAuthentication: true },
    create: { '*': true },
    update: { '*': true },
    delete: { '*': true },
    addField: { '*': true },
  };

  for (const [owner, ownerUrl, writer, writerUrl] of [
    ['parse-rust', RUST_URL, 'parse-server', UP_URL],
    ['parse-server', UP_URL, 'parse-rust', RUST_URL],
  ]) {
    const className = `SharedCLP_${owner.replace('-', '_')}_${TAG}`;
    await on(ownerUrl, async () => {
      const seed = new Parse.Object(className);
      seed.set('n', 1);
      await seed.save(null, MASTER);
    });
    await setCLP(ownerUrl, className, CLP);

    const stored = await schemaDoc(className);
    check(`${owner} stored a class_permissions block on ${className}`,
      !!stored?._metadata?.class_permissions, J(stored?._metadata));
    eq(`${owner}'s CLP kept requiresAuthentication on find`,
      stored?._metadata?.class_permissions?.find?.requiresAuthentication, true);
    const beforeWrite = J(stored?._metadata?.class_permissions);

    // An ordinary object write by the other server. Not a schema call: the point is that the
    // everyday path leaves the block alone.
    const written = await on(writerUrl, async () => {
      const row = new Parse.Object(className);
      row.set('n', 2);
      await row.save(null, MASTER);
      return row;
    });
    check(`${writer} wrote an ordinary object into ${className}`, typeof written.id === 'string');

    const after = await schemaDoc(className);
    eq(`${writer} left ${owner}'s class_permissions byte-identical`,
      J(after?._metadata?.class_permissions), beforeWrite);

    // And the block is still enforced afterwards, which is the thing the byte comparison stands
    // in for. An anonymous find is refused; an authenticated one is not.
    const anonymous = await on(writerUrl, () => outcome(() => new Parse.Query(className).find()));
    check(`${writer} still enforces ${owner}'s CLP anonymously`, anonymous.ok === false,
      `it returned ${J(anonymous.value)}`);
    eq(`${writer} refuses it as OBJECT_NOT_FOUND`, anonymous.code, Parse.Error.OBJECT_NOT_FOUND);
    const authenticated = await on(writerUrl, () => new Parse.Query(className).find(as(fromRust.token)));
    eq(`${writer} still allows an authenticated find under ${owner}'s CLP`, authenticated.length, 2);
  }

  // ---------------------------------------------------------------------------------------------
  // A failed write's schema side effect, which both servers have to agree about
  // ---------------------------------------------------------------------------------------------
  //
  // `enforceClassExists` runs from `validateSchema` before a single field is inspected
  // (`RestWrite.js:127-128`, `SchemaController.js:1288`), so a write to a class nobody has created
  // creates the class and *then* fails. That is a `_SCHEMA` row on a shared database, so the two
  // servers disagreeing about it is a fleet problem rather than a cosmetic one: one node creates
  // classes the other does not, and `GET /schemas` differs by which node served the write.
  //
  // **Raw HTTP, not the SDK.** `ParseObject.validate` refuses a key that does not match
  // `/^[A-Za-z][0-9A-Za-z_.]*$/` client-side, so `save()` rejects with `INVALID_KEY_NAME` without
  // sending anything. Driving this through the SDK measures the SDK: an earlier version of this
  // block did exactly that and reported both servers failing to create a class neither had been
  // asked to. Only a raw client, or a non-JavaScript SDK, can reach the server-side check.
  const restWrite = (url, className, objectId, body) =>
    fetch(`${url}/classes/${className}${objectId ? `/${objectId}` : ''}`, {
      method: objectId ? 'PUT' : 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Parse-Application-Id': APP_ID,
        'X-Parse-Master-Key': MASTER_KEY,
      },
      body: JSON.stringify(body),
    }).then(async r => ({ status: r.status, body: await r.json() }));

  for (const [who, url] of [['parse-rust', RUST_URL], ['parse-server', UP_URL]]) {
    const tag = who.replace('-', '');
    const cases = [
      ['an update with a valid body', 'doesNotExist', { n: 1 }, Parse.Error.OBJECT_NOT_FOUND, true],
      ['an update with an empty body', 'doesNotExist', {}, Parse.Error.OBJECT_NOT_FOUND, true],
      ['an update with a bad field name', 'doesNotExist', { 'bad-key': 1 }, Parse.Error.INVALID_KEY_NAME, true],
      ['a create with a bad field name', null, { 'bad-key': 1 }, Parse.Error.INVALID_KEY_NAME, true],
      // The one case that must **not** leave a row. `addClassIfNotExists` rejects an invalid class
      // name, the reload does not conjure it, and the terminal catch reports the fixed
      // `schema class name does not revalidate` as `INVALID_JSON` rather than the detailed 103 the
      // schema route gives for the same name (`SchemaController.js:987-1004`). Both halves matter:
      // the code, and that nothing is written. parse-rust answered 103 and wrote the row.
      ['a create with an invalid class name', null, { x: 1 }, Parse.Error.INVALID_JSON, false],
    ];
    for (const [i, [label, objectId, body, code, expectRow]] of cases.entries()) {
      // One class per case, because the precondition below is that the class does not exist yet.
      // The invalid-name case has to carry a name that fails `/^[A-Za-z][A-Za-z0-9_]*$/`.
      const className = expectRow ? `GateDGhost${tag}Case${i}` : `1GateDGhost${tag}Case${i}`;
      check(`${className} does not exist before ${who} is asked for ${label}`,
        (await schemaDoc(className)) === null);

      const failed = await restWrite(url, className, objectId, body);
      eq(`${who} refuses ${label} with the expected code`, failed.body.code, code);

      const row = await schemaDoc(className);
      if (expectRow) {
        check(`${who} left the ${className} schema row behind after ${label}`, row !== null,
          `the failed write must still have created the class: ${J(failed.body)}`);
      } else {
        check(`${who} wrote no schema row for ${label}`, row === null,
          `an invalid class name must not reach _SCHEMA: ${J(row)}`);
      }
    }
  }

  await db.dropDatabase();
  await client.close();

  if (failures.length) {
    console.error(`FAIL  shared-auth-state: ${failures.length} assertion(s):`);
    for (const f of failures) {
      console.error(`  - ${f}`);
    }
    process.exit(1);
  }
  if (passed < ASSERTION_FLOOR) {
    console.error(`FAIL  shared-auth-state ran ${passed} assertions, floor is ${ASSERTION_FLOOR}`);
    process.exit(1);
  }
  console.log(`OK  shared-auth-state: ${passed} assertions pass with both servers on one database`);
  process.exit(0);
}

main().catch(e => {
  console.error('harness error:', e && e.stack ? e.stack : e);
  process.exit(2);
});
