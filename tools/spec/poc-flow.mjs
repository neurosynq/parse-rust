/*
 * Gate A of the 0.1.0 milestone: the proof-of-concept flow, driven by the unmodified Parse SDK.
 *
 *   signup -> login -> create -> update one field -> query it back -> fetch by id -> logout
 *
 * Uses the real `parse` npm SDK rather than hand-written HTTP. Raw requests would let parse-rust
 * pass while breaking the thing the parity claim is actually about: the SDK encodes bodies, sets
 * headers and interprets responses in ways a curl command does not exercise.
 *
 * Point it at a real parse-server to check the harness itself. Every assertion here has been
 * verified to pass against parse-server 9.10.1-alpha.6, so a failure means parse-rust diverged
 * rather than that the expectation was invented.
 *
 * Usage:
 *   node tools/spec/poc-flow.mjs <server-url> [appId] [jsKey|-] [masterKey] [mongo-uri]
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
const Parse = require(`${PS_ROOT}/node_modules/parse/node`);

const [, , SERVER_URL, APP_ID = 'test', JS_KEY = '-', MASTER_KEY = 'test', MONGO_URI] = process.argv;
if (!SERVER_URL) {
  console.error('usage: node tools/spec/poc-flow.mjs <server-url> [appId] [jsKey|-] [masterKey]');
  process.exit(2);
}

// A floor, because a check that can pass by finding nothing will. If a block throws early, or one
// is dropped in a refactor, the run lands below this and fails rather than reporting a green suite
// that exercised a fraction of the flow. Raise it when assertions are added; never lower it to
// make a run pass. The Mongo-backed at-rest checks are conditional, so the floor is the count
// without them.
const ASSERTION_FLOOR = 40;

let passed = 0;
const failures = [];
function check(name, cond, detail = '') {
  if (cond) { passed++; } else { failures.push(`${name}${detail ? `: ${detail}` : ''}`); }
}
function eq(name, actual, expected) {
  check(name, actual === expected, `expected ${JSON.stringify(expected)}, got ${JSON.stringify(actual)}`);
}

// A unique username per run, so repeated runs against the same database do not collide on the
// unique index. Not random: derived from the pid and clock so a failure is traceable to a run.
const USERNAME = `poc_${process.pid}_${Date.now()}`;
const PASSWORD = 'correct horse battery staple';

Parse.initialize(APP_ID, JS_KEY === '-' ? undefined : JS_KEY, MASTER_KEY);
Parse.serverURL = SERVER_URL;

async function main() {
  // --- signup -------------------------------------------------------------
  const user = new Parse.User();
  user.set('username', USERNAME);
  user.set('password', PASSWORD);
  await user.signUp();

  check('signup returns an objectId', typeof user.id === 'string' && user.id.length === 10,
    `got ${JSON.stringify(user.id)}`);
  check('signup returns a session token', typeof user.getSessionToken() === 'string');
  check('the session token carries the r: prefix', user.getSessionToken().startsWith('r:'),
    user.getSessionToken());
  check('signup never returns the password', user.get('password') === undefined);

  // --- logout then log back in -------------------------------------------
  await Parse.User.logOut();
  const loggedIn = await Parse.User.logIn(USERNAME, PASSWORD);
  eq('login returns the same user', loggedIn.id, user.id);
  eq('login returns the username', loggedIn.get('username'), USERNAME);
  check('login never returns the password hash', loggedIn.get('_hashed_password') === undefined);
  check('login never returns a password field', loggedIn.get('password') === undefined);

  // --- a wrong password must fail, with the same error as an unknown user --
  let wrongPasswordFailed = false;
  try {
    await Parse.User.logIn(USERNAME, 'not the password');
  } catch (e) {
    wrongPasswordFailed = true;
    eq('a wrong password is OBJECT_NOT_FOUND', e.code, Parse.Error.OBJECT_NOT_FOUND);
  }
  check('a wrong password does not log in', wrongPasswordFailed);

  // Log back in for the rest of the flow.
  const self = await Parse.User.logIn(USERNAME, PASSWORD);

  // --- user.save() on an existing user ------------------------------------
  // The SDK sends this as `PUT /classes/_User/:objectId`, not `/users/:objectId`, which is why a
  // blanket refusal of non-master `_User` writes broke an ordinary profile edit. Driven through
  // the unmodified SDK because the route it picks is the whole point.
  //
  // `Parse.User.current()` is null here: the Node SDK has no storage controller in this harness,
  // so the object returned by `logIn` is the session-bearing one, and its token has to be passed
  // explicitly. With a real current user the SDK attaches it and `save()` takes no arguments.
  self.set('nickname', 'Sav');
  await self.save(null, { sessionToken: self.getSessionToken() });
  eq('user.save() persists a field', self.get('nickname'), 'Sav');

  const refetched = await Parse.User.logIn(USERNAME, PASSWORD);
  eq('the saved field survives a re-login', refetched.get('nickname'), 'Sav');
  check('a save response carries no password hash', refetched.get('_hashed_password') === undefined);

  // --- create -------------------------------------------------------------
  const Note = Parse.Object.extend('PocNote');
  const note = new Note();
  note.set('title', 'hello');
  note.set('views', 3);
  note.set('published', true);
  await note.save();

  check('create returns an objectId', typeof note.id === 'string' && note.id.length === 10);
  check('create sets createdAt', note.createdAt instanceof Date);
  check('createdAt is a real date, not an Invalid Date',
    !Number.isNaN(note.createdAt.getTime()),
    String(note.createdAt));

  // --- update one field ---------------------------------------------------
  note.set('views', 4);
  await note.save();
  check('update sets updatedAt', note.updatedAt instanceof Date);
  check('updatedAt is a real date', !Number.isNaN(note.updatedAt.getTime()));

  // --- query it back ------------------------------------------------------
  const q = new Parse.Query(Note);
  q.equalTo('title', 'hello');
  const found = await q.find();
  check('query returns the object', found.some(o => o.id === note.id),
    `got ${found.length} result(s)`);
  const fromQuery = found.find(o => o.id === note.id);
  eq('the updated value came back', fromQuery.get('views'), 4);
  eq('an untouched field survived', fromQuery.get('title'), 'hello');
  eq('a boolean round trips', fromQuery.get('published'), true);
  check('numbers come back as numbers', typeof fromQuery.get('views') === 'number');

  // --- fetch by id --------------------------------------------------------
  const byId = await new Parse.Query(Note).get(note.id);
  eq('fetch by id returns the object', byId.id, note.id);
  eq('fetch by id has the updated value', byId.get('views'), 4);

  // --- a type conflict is refused, with upstream's message -----------------
  let mismatchCode = null;
  let mismatchMessage = '';
  try {
    const bad = new Note();
    bad.set('title', 42); // title was inferred as String
    await bad.save();
  } catch (e) {
    mismatchCode = e.code;
    mismatchMessage = e.message;
  }
  eq('a type conflict is INCORRECT_TYPE', mismatchCode, Parse.Error.INCORRECT_TYPE);
  eq('the mismatch message is upstream’s',
    mismatchMessage,
    'schema mismatch for PocNote.title; expected String but got Number');

  // --- a duplicate username is USERNAME_TAKEN, not a raw duplicate-key -----
  let dupCode = null;
  let dupMessage = null;
  try {
    const dup = new Parse.User();
    dup.set('username', USERNAME);
    dup.set('password', 'whatever');
    await dup.signUp();
  } catch (e) {
    dupCode = e.code;
    dupMessage = e.message;
  }
  eq('a duplicate username is USERNAME_TAKEN', dupCode, Parse.Error.USERNAME_TAKEN);
  // The fixed message, which is also the assertion that no driver text reached the client: the
  // MongoDB `E11000` string names the database and quotes the colliding username.
  eq('the duplicate message is upstream’s',
    dupMessage,
    'Account already exists for this username.');

  // --- security assertions ------------------------------------------------
  //
  // Every one of these failed at some point while the gate above was passing, which is why they
  // are here: the flow assertions only cover the path the author had in mind.

  // 1. A master `_User` write through /classes must use the same safe password outcome as signup.
  //
  //    An API read is not enough evidence: response filtering can hide a plaintext stored field.
  //    Logging in proves the stored credential is a usable password hash, while the read verifies
  //    that neither password representation reaches a response.
  const sneakUsername = `${USERNAME}_sneak`;
  const sneakPassword = 'PLAINTEXT';
  const sneak = new Parse.Object('_User');
  sneak.set('username', sneakUsername);
  sneak.set('password', sneakPassword);
  await sneak.save(null, { useMasterKey: true });

  const sneakLogin = await Parse.User.logIn(sneakUsername, sneakPassword);
  eq('a master class-created user can log in', sneakLogin.id, sneak.id);
  const sneakBack = await new Parse.Query(Parse.User)
    .equalTo('username', sneakUsername)
    .first({ useMasterKey: true });
  check('a _User read never returns password', sneakBack?.get('password') === undefined);
  check('a _User read never returns the password hash',
    sneakBack?.get('_hashed_password') === undefined);

  // Response filtering cannot establish an at-rest property, so the harness passes its disposable
  // database URI when one is available and inspects the row itself.
  if (MONGO_URI) {
    const { MongoClient } = require(`${PS_ROOT}/node_modules/mongodb`);
    const client = await MongoClient.connect(MONGO_URI);
    const database = new URL(MONGO_URI).pathname.replace(/^\//, '');
    const stored = await client.db(database).collection('_User').findOne({ _id: sneak.id });
    check('a master class-created user has a stored password hash',
      typeof stored?._hashed_password === 'string');
    check('a master class-created user has no stored plaintext password',
      stored?.password === undefined);
    await client.close();
  }

  // 2. An ACL round trips. This never worked until it was tested: an incoming ACL was rejected by
  //    the schema, and a stored one was dropped before it could be rebuilt.
  //
  //    Session tokens are passed explicitly rather than relying on `Parse.User.current()`. In
  //    Node there is no storage controller, so there is no persisted current user and an
  //    "authenticated" call would silently go out anonymous, which would make these assertions
  //    test the wrong thing.
  const me = await Parse.User.logIn(USERNAME, PASSWORD);
  const meToken = me.getSessionToken();

  const priv = new Note();
  priv.set('title', 'private');
  const acl = new Parse.ACL();
  acl.setReadAccess(me.id, true);
  acl.setWriteAccess(me.id, true);
  priv.setACL(acl);
  await priv.save(null, { sessionToken: meToken });

  const readBack = await new Parse.Query(Note).get(priv.id, { sessionToken: meToken });
  check('an ACL survives the round trip', !!readBack.getACL(), 'no ACL came back');
  check('the ACL grants its owner read', readBack.getACL()?.getReadAccess(me.id) === true);

  // 3. A second user cannot read the first user's private row.
  const other = new Parse.User();
  other.set('username', `${USERNAME}_other`);
  other.set('password', PASSWORD);
  await other.signUp();
  const otherToken = other.getSessionToken();

  let otherSawIt = true;
  try {
    await new Parse.Query(Note).get(priv.id, { sessionToken: otherToken });
  } catch (e) {
    otherSawIt = false;
    eq('a private row is OBJECT_NOT_FOUND to another user', e.code, Parse.Error.OBJECT_NOT_FOUND);
  }
  check('a private row is not readable by another user', !otherSawIt);

  // 4. And cannot write it either.
  let otherWrote = true;
  try {
    readBack.set('title', 'tampered');
    await readBack.save(null, { sessionToken: otherToken });
  } catch (e) {
    otherWrote = false;
    eq('a private row is not writable by another user', e.code, Parse.Error.OBJECT_NOT_FOUND);
  }
  check('a private row is not writable by another user', !otherWrote);

  // 5. A new user is private. Without the signup ACL, every user was world readable.
  const usersVisible = await new Parse.Query(Parse.User).find({ sessionToken: otherToken });
  check('a user cannot list other users',
    usersVisible.every(u => u.id === other.id),
    `saw ${usersVisible.length}: ${usersVisible.map(u => u.get('username')).join(', ')}`);

  // 6. An invalid session token is rejected rather than silently downgraded to anonymous.
  const badToken = await fetch(`${SERVER_URL}/classes/PocNote`, {
    headers: {
      'X-Parse-Application-Id': APP_ID,
      'X-Parse-Session-Token': 'r:definitely-not-a-real-token',
    },
  }).then(r => r.json());
  eq('an unknown session token is 209', badToken.code, Parse.Error.INVALID_SESSION_TOKEN);

  // --- logout -------------------------------------------------------------
  await Parse.User.logOut();
  const current = await Parse.User.currentAsync();
  check('logout clears the current user', current === null, JSON.stringify(current));

  if (failures.length) {
    console.error(`FAIL  ${failures.length} assertion(s) against ${SERVER_URL}:`);
    for (const f of failures) { console.error(`  - ${f}`); }
    process.exit(1);
  }
  if (passed < ASSERTION_FLOOR) {
    console.error(`FAIL  poc-flow ran ${passed} assertions, floor is ${ASSERTION_FLOOR}`);
    process.exit(1);
  }
  console.log(`OK  poc-flow: ${passed} assertions pass against ${SERVER_URL}`);
  process.exit(0);
}

main().catch(e => {
  console.error(`harness error against ${SERVER_URL}:`, e && e.message ? e.message : e);
  process.exit(2);
});
