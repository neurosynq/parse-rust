/*
 * Gate C of the 0.2.0 milestone: the authorization model, driven by the unmodified Parse SDK.
 *
 * Five cases, each one a thing 0.1.0 could not do: role ACLs, nested and cyclic role graphs,
 * `requiresAuthentication`, pointer permissions, and protected fields.
 *
 * **Every assertion in this file must also pass against real parse-server.** That property is the
 * only thing that makes a failure here mean "parse-rust diverged" rather than "someone typed an
 * expectation". It is also a constraint on what may be added: a single parse-rust-specific
 * assertion breaks the promise silently, because the file keeps claiming to be differential while
 * no longer being runnable against upstream. Deliberate divergences are asserted in the Rust tests
 * instead, in `crates/parse-rust-server/tests/`. Nothing in this file enforces that rule, so run
 * `--upstream` and keep it green.
 *
 * Two habits this file exists to keep, both of them scars:
 *
 * - **Assert the caller can see its own data before asserting it cannot see anyone else's.**
 *   A server that denies everything passes an isolation test that only checks the denial. Each
 *   case therefore carries a control row the denied caller *can* read.
 * - **Never let an "anonymous" request carry a token.** In Node the SDK's current-user support is
 *   off by default, so an SDK call with no `sessionToken` goes out anonymous, which is what makes
 *   the anonymous sweeps meaningful. `disableUnsafeCurrentUser()` below states that rather than
 *   relying on it, and the sweeps assert there is no current user before they run.
 *
 * Usage:
 *   node tools/spec/authorization.mjs <server-url> [appId] [masterKey] [--upstream=<mongo-uri>]
 *                                     [--detailed]
 *
 * With `--upstream`, the runner additionally boots parse-server 9.10.1-alpha.6 from the checkout
 * on its own database and replays every assertion there, then requires both targets to have run
 * the same named assertions. Without it, only the given URL is exercised and the summary says so.
 *
 * `--detailed` says the target server was booted with `enableSanitizedErrorResponse: false`, and
 * boots the upstream half the same way. Without it both sides run at the upstream default, which
 * is `true` (`Options/Definitions.js:259-264`) and is therefore the configuration a real
 * deployment has. The two regimes carry different messages on the wire and both are contract, so
 * `tools/test.sh` runs the gate once each way rather than picking one.
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

const argv = process.argv.slice(2);
const upstreamFlag = argv.find(a => a.startsWith('--upstream'));
const positional = argv.filter(a => !a.startsWith('--'));
const [SERVER_URL, APP_ID = 'test', MASTER_KEY = 'test'] = positional;
const UPSTREAM_URI = upstreamFlag ? upstreamFlag.split('=').slice(1).join('=') : undefined;
/** True when the target runs with `enableSanitizedErrorResponse: false`. */
const DETAILED = argv.includes('--detailed');

if (!SERVER_URL) {
  console.error('usage: node tools/spec/authorization.mjs <server-url> [appId] [masterKey] [--upstream=<mongo-uri>] [--detailed]');
  process.exit(2);
}
if (upstreamFlag && !UPSTREAM_URI) {
  console.error('--upstream needs a mongo URI: --upstream=mongodb://127.0.0.1:27017/<db>');
  process.exit(2);
}

// A floor, because a check that can pass by finding nothing will. If a case throws early, or a
// refactor drops a block, the run has fewer assertions than this and fails as a harness error
// rather than reporting a green suite that tested a fraction of the surface. Raise it when cases
// are added; never lower it to make a run pass.
const ASSERTION_FLOOR = 85;

const PASSWORD = 'correct horse battery staple';
const RUN = `${process.pid}x${Date.now().toString(36)}`;

/**
 * The message a denial carries.
 *
 * Every string below comes from a `createSanitizedError` call site, so at the upstream default
 * the client sees the generic `Permission denied` and the detailed text exists only server-side.
 * Asserting the detailed form unconditionally is what made an earlier version of this gate need
 * `enableSanitizedErrorResponse: false` on the upstream half, which measured a configuration no
 * deployment runs.
 */
const SANITIZED = 'Permission denied';
const denial = detailed => (DETAILED ? detailed : SANITIZED);

// -----------------------------------------------------------------------------------------------
// Recording
// -----------------------------------------------------------------------------------------------

function J(v) {
  return JSON.stringify(v);
}

function recorder(label) {
  return {
    label,
    names: [],
    failures: [],
    check(name, cond, detail = '') {
      this.names.push(name);
      if (!cond) {
        this.failures.push(`${name}${detail ? `: ${detail}` : ''}`);
      }
    },
    eq(name, actual, expected) {
      this.check(name, actual === expected, `expected ${J(expected)}, got ${J(actual)}`);
    },
  };
}

/** Run `fn`, returning either its value or the Parse error it threw. Never throws. */
async function outcome(fn) {
  try {
    return { ok: true, value: await fn() };
  } catch (e) {
    return { ok: false, code: e?.code, message: e?.message };
  }
}

/** A request that must be refused, with an exact code and, where it is contract, an exact message. */
async function assertDenied(r, name, fn, code, message) {
  const got = await outcome(fn);
  r.check(`${name}: refused`, got.ok === false, `it succeeded with ${J(got.value)}`);
  r.eq(`${name}: code`, got.code, code);
  if (message !== undefined) {
    r.eq(`${name}: message`, got.message, message);
  }
}

/**
 * A hard deadline, so a role graph that fails to terminate fails the run instead of hanging it.
 * The cycle case is the whole reason this exists.
 */
function withTimeout(promise, ms, label) {
  let timer;
  return Promise.race([
    promise,
    new Promise((_, reject) => {
      timer = setTimeout(() => reject(new Error(`${label} did not terminate within ${ms}ms`)), ms);
    }),
  ]).finally(() => clearTimeout(timer));
}

// -----------------------------------------------------------------------------------------------
// SDK helpers. Every authenticated call passes its session token explicitly.
// -----------------------------------------------------------------------------------------------

const MASTER = { useMasterKey: true };
const as = token => ({ sessionToken: token });

async function signUp(tag, name) {
  const user = new Parse.User();
  user.set('username', `${name}_${tag}`);
  user.set('password', PASSWORD);
  await user.signUp();
  return { id: user.id, token: user.getSessionToken() };
}

/** A role with public read on its own row, holding the given users. */
async function createRole(tag, name, userIds) {
  const acl = new Parse.ACL();
  acl.setPublicReadAccess(true);
  const role = new Parse.Role(`${name}_${tag}`, acl);
  for (const id of userIds) {
    role.getUsers().add(Parse.User.createWithoutData(id));
  }
  await role.save(null, MASTER);
  return role;
}

/** `parent` contains `child`, so a member of `child` inherits `parent`. */
async function nestRole(parent, child) {
  const p = Parse.Role.createWithoutData(parent.id);
  p.getRoles().add(child);
  await p.save(null, MASTER);
}

/** An object readable only through the given ACL builder, written with the master key. */
async function saveWithACL(className, values, buildACL) {
  const object = new Parse.Object(className);
  object.set(values);
  const acl = new Parse.ACL();
  buildACL(acl);
  object.setACL(acl);
  await object.save(null, MASTER);
  return object;
}

/**
 * Replace a class's CLP through `Parse.Schema`, which drives `POST`/`PUT /schemas/:className` with
 * the master key. Using the SDK rather than raw `fetch` means the gate also proves the SDK's own
 * schema path works, which parse-dashboard depends on and no client SDK flow exercises.
 *
 * `update()` when the class exists, `save()` when it does not: `POST` on an existing class is
 * `Class <X> already exists.` upstream.
 */
async function setCLP(className, clp) {
  const schema = new Parse.Schema(className);
  schema.setCLP(clp);
  const exists = await outcome(() => new Parse.Schema(className).get());
  return exists.ok ? schema.update() : schema.save();
}

// -----------------------------------------------------------------------------------------------
// Case 1: a role ACL grants its members and nobody else
// -----------------------------------------------------------------------------------------------

async function caseRoleAcl(r, tag) {
  const Doc = `AuthzDoc_${tag}`;
  const member = await signUp(tag, 'c1_member');
  const outsider = await signUp(tag, 'c1_outsider');
  await createRole(tag, 'Readers', [member.id]);
  const roleName = `Readers_${tag}`;

  // The control row. Without it, a server that hides everything from everyone passes this case.
  await saveWithACL(Doc, { title: 'public' }, acl => acl.setPublicReadAccess(true));
  const restricted = await saveWithACL(Doc, { title: 'restricted' }, acl =>
    acl.setRoleReadAccess(roleName, true));

  // The member sees it. This is the assertion 0.1.0 could not make: `role:` matched nobody.
  const seen = await new Parse.Query(Doc).get(restricted.id, as(member.token));
  r.eq('role member reads the role-ACLed row', seen.get('title'), 'restricted');
  const memberList = await new Parse.Query(Doc).find(as(member.token));
  r.eq('role member lists both rows', memberList.length, 2);

  // The outsider is a working caller who happens not to hold the role.
  const outsiderList = await new Parse.Query(Doc).find(as(outsider.token));
  r.eq('non-member lists only the public row', outsiderList.length, 1);
  r.eq('non-member sees the public row', outsiderList[0]?.get('title'), 'public');

  await assertDenied(r, 'non-member get on a role-ACLed row',
    () => new Parse.Query(Doc).get(restricted.id, as(outsider.token)),
    Parse.Error.OBJECT_NOT_FOUND);

  r.check('no current user before the anonymous read', (await Parse.User.currentAsync()) === null);
  const anonList = await new Parse.Query(Doc).find();
  r.eq('anonymous lists only the public row', anonList.length, 1);
  await assertDenied(r, 'anonymous get on a role-ACLed row',
    () => new Parse.Query(Doc).get(restricted.id),
    Parse.Error.OBJECT_NOT_FOUND);
}

// -----------------------------------------------------------------------------------------------
// Case 2: nesting is transitive, and a cycle terminates
// -----------------------------------------------------------------------------------------------

async function caseRoleGraph(r, tag) {
  const Doc = `AuthzNest_${tag}`;
  const member = await signUp(tag, 'c2_member');
  const outsider = await signUp(tag, 'c2_outsider');

  // The member is in Juniors, Seniors contains Juniors, so the member holds Seniors.
  const juniors = await createRole(tag, 'Juniors', [member.id]);
  const seniors = await createRole(tag, 'Seniors', []);
  await nestRole(seniors, juniors);

  await saveWithACL(Doc, { title: 'public' }, acl => acl.setPublicReadAccess(true));
  const seniorOnly = await saveWithACL(Doc, { title: 'senior only' }, acl =>
    acl.setRoleReadAccess(`Seniors_${tag}`, true));

  const inherited = await withTimeout(
    new Parse.Query(Doc).get(seniorOnly.id, as(member.token)), 20000, 'nested role read');
  r.eq('a nested role is inherited transitively', inherited.get('title'), 'senior only');
  await assertDenied(r, 'a non-member does not inherit the parent role',
    () => new Parse.Query(Doc).get(seniorOnly.id, as(outsider.token)),
    Parse.Error.OBJECT_NOT_FOUND);

  // A contains B and B contains A. The member is in A directly, so the expansion reaches B through
  // the cycle and has to stop. Both names must resolve, and neither read may hang.
  const cycleA = await createRole(tag, 'CycleA', [member.id]);
  const cycleB = await createRole(tag, 'CycleB', []);
  await nestRole(cycleA, cycleB);
  await nestRole(cycleB, cycleA);

  const viaA = await saveWithACL(Doc, { title: 'cycle a' }, acl =>
    acl.setRoleReadAccess(`CycleA_${tag}`, true));
  const viaB = await saveWithACL(Doc, { title: 'cycle b' }, acl =>
    acl.setRoleReadAccess(`CycleB_${tag}`, true));

  const readA = await withTimeout(
    new Parse.Query(Doc).get(viaA.id, as(member.token)), 20000, 'cyclic role read (direct)');
  r.eq('a cycle does not lose the directly held role', readA.get('title'), 'cycle a');
  const readB = await withTimeout(
    new Parse.Query(Doc).get(viaB.id, as(member.token)), 20000, 'cyclic role read (through cycle)');
  r.eq('a cycle resolves the far side and terminates', readB.get('title'), 'cycle b');

  // The cycle grants the two names it contains, not every name.
  await assertDenied(r, 'a cycle does not grant a role to a non-member',
    () => new Parse.Query(Doc).get(viaB.id, as(outsider.token)),
    Parse.Error.OBJECT_NOT_FOUND);
}

// -----------------------------------------------------------------------------------------------
// Case 3: requiresAuthentication, and the code is 101 rather than 119
// -----------------------------------------------------------------------------------------------

async function caseRequiresAuthentication(r, tag) {
  const Guarded = `AuthzGuarded_${tag}`;
  const user = await signUp(tag, 'c3_user');

  const row = new Parse.Object(Guarded);
  row.set('n', 1);
  await row.save(null, MASTER);

  await setCLP(Guarded, {
    find: { requiresAuthentication: true },
    get: { requiresAuthentication: true },
    count: { requiresAuthentication: true },
    create: { '*': true },
    update: { '*': true },
    delete: { '*': true },
    addField: { '*': true },
  });

  // The authenticated read first: a class nobody can read passes the denial assertions below.
  const allowed = await new Parse.Query(Guarded).find(as(user.token));
  r.eq('an authenticated find succeeds under requiresAuthentication', allowed.length, 1);
  const fetched = await new Parse.Query(Guarded).get(row.id, as(user.token));
  r.eq('an authenticated get succeeds under requiresAuthentication', fetched.get('n'), 1);

  r.check('no current user before the anonymous query', (await Parse.User.currentAsync()) === null);

  const DENIED = denial('Permission denied, user needs to be authenticated.');
  const anonymousFind = await outcome(() => new Parse.Query(Guarded).find());
  r.check('an anonymous find is refused', anonymousFind.ok === false,
    `it returned ${J(anonymousFind.value)}`);
  r.eq('an anonymous find is OBJECT_NOT_FOUND', anonymousFind.code, Parse.Error.OBJECT_NOT_FOUND);
  r.eq('an anonymous find carries the authentication message', anonymousFind.message, DENIED);
  // Spelled out rather than implied. Existence hiding is the deliberate part: 119 would tell an
  // unauthenticated caller that the class is there and guarded, and 101 does not.
  r.eq('an anonymous find is code 101', anonymousFind.code, 101);
  r.check('an anonymous find is not OPERATION_FORBIDDEN',
    anonymousFind.code !== Parse.Error.OPERATION_FORBIDDEN, 'got 119');

  await assertDenied(r, 'an anonymous get under requiresAuthentication',
    () => new Parse.Query(Guarded).get(row.id), 101, DENIED);
  await assertDenied(r, 'an anonymous count under requiresAuthentication',
    () => new Parse.Query(Guarded).count(), 101, DENIED);
}

// -----------------------------------------------------------------------------------------------
// Case 4: pointer permissions narrow the query, and deny-all is not "no constraint"
// -----------------------------------------------------------------------------------------------

async function casePointerPermissions(r, tag) {
  const Owned = `AuthzOwned_${tag}`;
  const a = await signUp(tag, 'c4_a');
  const b = await signUp(tag, 'c4_b');

  const rows = {};
  for (const [who, user] of [['a', a], ['b', b]]) {
    const row = new Parse.Object(Owned);
    row.set('owner', Parse.User.createWithoutData(user.id));
    row.set('title', `owned by ${who}`);
    await row.save(null, MASTER);
    rows[who] = row;
  }

  await setCLP(Owned, {
    find: { pointerFields: ['owner'] },
    get: { pointerFields: ['owner'] },
    count: { pointerFields: ['owner'] },
    create: { pointerFields: ['owner'] },
    update: { pointerFields: ['owner'] },
    delete: { pointerFields: ['owner'] },
    addField: { '*': true },
  });

  // Each owner sees exactly their own row. Assert this before the anonymous sweep: the sweep
  // passes just as well against a class nobody can read at all.
  for (const [who, user] of [['a', a], ['b', b]]) {
    const mine = await new Parse.Query(Owned).find(as(user.token));
    r.eq(`${who} finds one row`, mine.length, 1);
    r.eq(`${who} finds only its own row`, mine[0]?.get('title'), `owned by ${who}`);
    r.eq(`${who} counts one row`, await new Parse.Query(Owned).count(as(user.token)), 1);
    const got = await new Parse.Query(Owned).get(rows[who].id, as(user.token));
    r.eq(`${who} gets its own row`, got.id, rows[who].id);
  }

  // **The client naming the permission field itself.** Both predicates have to survive, and
  // upstream is explicit about it: `addPointerPermissions` tests whether the query already
  // constrains the key and conjoins under `$and` when it does
  // (`DatabaseController.js:1808-1812`). Appending the permission constraint beside the client's
  // instead produces two equalities on one field, which answers `INVALID_QUERY` rather than the
  // row. This is the ordinary case for an owner-scoped app, not an edge case.
  for (const [who, user] of [['a', a], ['b', b]]) {
    const explicit = await new Parse.Query(Owned)
      .equalTo('owner', Parse.User.createWithoutData(user.id))
      .find(as(user.token));
    r.eq(`${who} may query its own rows by owner`, explicit.length, 1);
    r.eq(`${who} reads the row it asked for by owner`, explicit[0]?.get('title'), `owned by ${who}`);
  }

  // Naming someone else's is an empty result rather than an error or a leak: the two predicates
  // conjoin, so the client's cannot displace the server's.
  const crossed = await new Parse.Query(Owned)
    .equalTo('owner', Parse.User.createWithoutData(b.id))
    .find(as(a.token));
  r.eq('a asking for b\'s rows by owner gets nothing', crossed.length, 0);

  // Stage one is a gate and stage two is a filter. A logged-in caller passes the gate and is
  // still confined to their own rows.
  await assertDenied(r, 'a gets b\'s row', () => new Parse.Query(Owned).get(rows.b.id, as(a.token)),
    Parse.Error.OBJECT_NOT_FOUND);
  const theirs = Parse.Object.fromJSON({ className: Owned, objectId: rows.b.id });
  theirs.set('title', 'taken');
  await assertDenied(r, 'a updates b\'s row', () => theirs.save(null, as(a.token)),
    Parse.Error.OBJECT_NOT_FOUND);

  // `create` under a pointer permission is a write lockdown rather than a narrowed query: the
  // create entry is present and unmatched, so it is refused for the owner too, not only for the
  // anonymous caller (`SchemaController.js:1425-1433`).
  const forbidden = denial(`Permission denied for action create on class ${Owned}.`);
  const ownCreate = new Parse.Object(Owned);
  ownCreate.set('owner', Parse.User.createWithoutData(a.id));
  ownCreate.set('title', 'new');
  await assertDenied(r, 'an owner creates under a create pointer permission',
    () => ownCreate.save(null, as(a.token)), Parse.Error.OPERATION_FORBIDDEN, forbidden);

  r.check('no current user before the anonymous sweep', (await Parse.User.currentAsync()) === null);

  // The `DenyAll`-reaching-a-caller-as-"no constraint" sweep. Every verb, not just find.
  const anonFind = await new Parse.Query(Owned).find();
  r.eq('an anonymous find returns nothing, not everything', anonFind.length, 0);

  // The two servers report the same emptiness in two shapes, so the assertion names both rather
  // than picking one and going red. Upstream's deny-all branch distinguishes `get` from everything
  // else and falls through to `return []` (`DatabaseController.js:1510-1515`), so a denied count
  // answers `{"results":[],"count":[]}` instead of `count: 0`. parse-rust answers `0`. Neither
  // discloses anything, and the difference is unrecorded rather than deliberate, so it is a
  // reported finding rather than a rule this file gets to settle.
  const anonCount = await new Parse.Query(Owned).count();
  r.check('an anonymous count reports no rows',
    anonCount === 0 || (Array.isArray(anonCount) && anonCount.length === 0),
    `got ${J(anonCount)}`);
  await assertDenied(r, 'an anonymous get', () => new Parse.Query(Owned).get(rows.a.id),
    Parse.Error.OBJECT_NOT_FOUND);

  const anonCreate = new Parse.Object(Owned);
  anonCreate.set('owner', Parse.User.createWithoutData(a.id));
  anonCreate.set('title', 'new');
  await assertDenied(r, 'an anonymous create', () => anonCreate.save(),
    Parse.Error.OPERATION_FORBIDDEN, forbidden);

  const anonUpdate = Parse.Object.fromJSON({ className: Owned, objectId: rows.a.id });
  anonUpdate.set('title', 'taken');
  await assertDenied(r, 'an anonymous update', () => anonUpdate.save(),
    Parse.Error.OBJECT_NOT_FOUND);
  const anonDelete = Parse.Object.fromJSON({ className: Owned, objectId: rows.a.id });
  await assertDenied(r, 'an anonymous delete', () => anonDelete.destroy(),
    Parse.Error.OBJECT_NOT_FOUND);

  // Nothing above landed.
  const after = await new Parse.Query(Owned).get(rows.a.id, MASTER);
  r.eq('no denied write mutated the row', after.get('title'), 'owned by a');
  r.eq('no denied create added a row', await new Parse.Query(Owned).count(MASTER), 2);

  // The owner's own delete still works, which is what proves the filter narrowed rather than
  // closed the verb.
  await new Parse.Query(Owned).get(rows.a.id, as(a.token)).then(o => o.destroy(as(a.token)));
  r.eq('an owner deletes its own row', await new Parse.Query(Owned).count(MASTER), 1);
}

// -----------------------------------------------------------------------------------------------
// Case 5: protected fields are absent, and cannot be probed through where or order
// -----------------------------------------------------------------------------------------------

async function caseProtectedFields(r, tag) {
  const Profile = `AuthzProfile_${tag}`;
  const user = await signUp(tag, 'c5_user');

  const profile = new Parse.Object(Profile);
  profile.set({ nickname: 'visible', secret: 'hidden' });
  await profile.save(null, MASTER);

  // The field exists before it is protected, so its later absence is stripping rather than a
  // write that never happened.
  const beforeProtection = await new Parse.Query(Profile).get(profile.id, MASTER);
  r.eq('the field is stored', beforeProtection.get('secret'), 'hidden');

  // `find` and `get` are spelled out: a stored block is merged over `emptyCLPS`, whose
  // unspecified operations are `{}`, so a block carrying only `protectedFields` closes the class.
  await setCLP(Profile, {
    find: { '*': true },
    get: { '*': true },
    count: { '*': true },
    create: { '*': true },
    update: { '*': true },
    delete: { '*': true },
    addField: { '*': true },
    protectedFields: { '*': ['secret'] },
  });

  const read = await new Parse.Query(Profile).get(profile.id, as(user.token));
  r.eq('the row is still readable', read.get('nickname'), 'visible');
  r.eq('the protected field is absent from a read', read.get('secret'), undefined);
  const listed = await new Parse.Query(Profile).find(as(user.token));
  r.eq('the row is still findable', listed.length, 1);
  r.eq('the protected field is absent from a find', listed[0]?.get('secret'), undefined);

  // Filtering the response is not enough. Without the query-side deny a client binary-searches the
  // value through `where` and `order`, so both are refused rather than quietly narrowed.
  await assertDenied(r, 'querying a protected field',
    () => new Parse.Query(Profile).equalTo('secret', 'hidden').find(as(user.token)),
    Parse.Error.OPERATION_FORBIDDEN,
    denial(`This user is not allowed to query secret on class ${Profile}`));
  await assertDenied(r, 'ordering by a protected field',
    () => new Parse.Query(Profile).ascending('secret').find(as(user.token)),
    Parse.Error.OPERATION_FORBIDDEN,
    denial(`This user is not allowed to sort by secret on class ${Profile}`));
  await assertDenied(r, 'querying a protected field anonymously',
    () => new Parse.Query(Profile).equalTo('secret', 'hidden').find(),
    Parse.Error.OPERATION_FORBIDDEN,
    denial(`This user is not allowed to query secret on class ${Profile}`));

  // Master is never protected, on either side.
  const master = await new Parse.Query(Profile).equalTo('secret', 'hidden').find(MASTER);
  r.eq('the master key still queries the protected field', master.length, 1);
  r.eq('the master key still reads the protected field', master[0]?.get('secret'), 'hidden');
}

// -----------------------------------------------------------------------------------------------
// Case 6: an include is a `get` for one id and a `find` for several, and the difference is a gate
// -----------------------------------------------------------------------------------------------

/**
 * `includePath` picks its method from the number of ids it collected, `get` for one and `find` for
 * several (`RestQuery.js:1250-1251`), while pinning the CLP operation to `get` for both
 * (`:1259`). Only `enforceRoleSecurity` sees the difference, and `_Installation` is where it
 * shows: clients may `get` an installation and may not `find` one (`SharedRest.js:14-22`).
 *
 * Deriving the method from the query shape instead makes every include a `get`, which hands a
 * client the whole installation collection a page at a time. Both halves are asserted, because
 * asserting only the refusal would also pass against a server that refuses every include.
 */
async function caseIncludeMethod(r, tag) {
  const Device = `AuthzDevice_${tag}`;
  const user = await signUp(tag, 'c6_user');

  // Two rows pointing at two different installations. The installations need not exist: the
  // method check runs before anything is read.
  for (const [name, id] of [['one', `i${tag}AAAA`], ['two', `i${tag}BBBB`]]) {
    const row = new Parse.Object(Device);
    row.set('tag', name);
    row.set('inst', Parse.Object.fromJSON({ className: '_Installation', objectId: id }));
    await row.save(null, MASTER);
  }

  const single = await new Parse.Query(Device)
    .equalTo('tag', 'one')
    .include('inst')
    .find(as(user.token));
  r.eq('an include collecting one id is a get and is allowed', single.length, 1);

  await assertDenied(r, 'an include collecting several ids is a find and is refused',
    () => new Parse.Query(Device).containedIn('tag', ['one', 'two']).include('inst').find(as(user.token)),
    Parse.Error.OPERATION_FORBIDDEN,
    denial('Clients aren\'t allowed to perform the find operation on the installation collection.'));

  // Without the include the same query is fine, which is what shows the refusal came from the
  // nested read rather than from the outer class.
  const plain = await new Parse.Query(Device).containedIn('tag', ['one', 'two']).find(as(user.token));
  r.eq('the same query without the include is allowed', plain.length, 2);
}

// -----------------------------------------------------------------------------------------------

async function suite(serverURL, tag, label) {
  const r = recorder(label);
  Parse.serverURL = serverURL;
  await caseRoleAcl(r, tag);
  await caseRoleGraph(r, tag);
  await caseRequiresAuthentication(r, tag);
  await casePointerPermissions(r, tag);
  await caseProtectedFields(r, tag);
  await caseIncludeMethod(r, tag);
  return r;
}

function report(r) {
  if (r.failures.length) {
    console.error(`FAIL  authorization against ${r.label}: ${r.failures.length} assertion(s):`);
    for (const f of r.failures) {
      console.error(`  - ${f}`);
    }
    return false;
  }
  return true;
}

async function main() {
  Parse.initialize(APP_ID, undefined, MASTER_KEY);
  // In Node the SDK does not persist a current user, so a call with no `sessionToken` goes out
  // anonymous. Stated rather than assumed: an "anonymous" request that silently carried a token
  // would make every denial assertion below prove nothing.
  Parse.User.disableUnsafeCurrentUser();

  const results = [];
  results.push(await suite(SERVER_URL, `${RUN}t`, SERVER_URL));

  let upstream;
  if (UPSTREAM_URI) {
    const { ParseServer } = require(`${PS_ROOT}/lib/index.js`);
    // Its own database. Sharing one with the target would collide on `_Role.name`'s unique index
    // and on class CLPs, and sharing is Gate D's subject rather than this one's.
    const uri = UPSTREAM_URI.replace(/\/([^/?]+)(\?|$)/, '/$1_upstream$2');
    // `allowClientClassCreation` is set on both sides. parse-rust implements the option and
    // defaults it to `false` as upstream does, so this is not papering over a gap; it is turning
    // one knob the same way on both servers. Leaving them configured differently would make the
    // CLP assertions measure the option instead of the authorization model.
    //
    // **`directAccess: false` is load-bearing, not tidying.** It defaults to `true`
    // (`Options/Definitions.js:191-196`), and when it is on, `ParseServer.startApp` replaces the
    // SDK's REST controller with an in-process router (`ParseServer.ts:370-372`). Every subsequent
    // SDK call in this process then goes to *upstream*, whatever `Parse.serverURL` says, and a
    // differential runner quietly stops being differential: it measures parse-server against
    // parse-server and reports green. Turning it off restores real HTTP, which is the only thing
    // that makes `Parse.serverURL` mean anything here.
    upstream = await ParseServer.startApp({
      appId: APP_ID,
      masterKey: MASTER_KEY,
      databaseURI: uri,
      serverURL: 'http://127.0.0.1/parse',
      mountPath: '/parse',
      port: 0,
      silent: true,
      allowClientClassCreation: true,
      directAccess: false,
      // Matched to whatever the target was booted with. Left at the default (`true`) this is the
      // configuration a real deployment runs, and the gate asserts the generic message on both
      // sides; `--detailed` runs both sides with it off and asserts the detailed strings, which
      // are equally contract. Configuring only one side would measure the option instead of the
      // authorization model.
      enableSanitizedErrorResponse: !DETAILED,
    });
    const url = `http://127.0.0.1:${upstream.server.address().port}/parse`;
    results.push(await suite(url, `${RUN}u`, `parse-server (${url})`));

    // Drop the database this gate created. The one parse-rust is using belongs to the harness that
    // booted it; this one exists only because the upstream half ran, so leaving it behind means a
    // stray database per run on every developer machine.
    const { MongoClient } = require(`${PS_ROOT}/node_modules/mongodb`);
    const client = await MongoClient.connect(uri);
    await client.db(new URL(uri).pathname.replace(/^\//, '')).dropDatabase();
    await client.close();
  }

  let ok = true;
  for (const r of results) {
    ok = report(r) && ok;
    if (r.names.length < ASSERTION_FLOOR) {
      console.error(`FAIL  ${r.label} ran ${r.names.length} assertions, floor is ${ASSERTION_FLOOR}`);
      ok = false;
    }
  }

  // The differential itself: both targets must have executed the same assertions in the same
  // order. A case that threw early on one side would otherwise report a shorter green run, and
  // "both passed" would mean "both passed the parts they reached".
  if (results.length === 2) {
    const [lhs, rhs] = results;
    const only = (a, b) => a.names.filter(n => !b.names.includes(n));
    const missing = [...only(lhs, rhs), ...only(rhs, lhs)];
    if (missing.length) {
      console.error(`FAIL  the two targets did not run the same assertions: ${missing.join(', ')}`);
      ok = false;
    }
    const first = lhs.names.findIndex((n, i) => n !== rhs.names[i]);
    if (lhs.names.length !== rhs.names.length || first !== -1) {
      const at = first === -1 ? Math.min(lhs.names.length, rhs.names.length) : first;
      console.error(`FAIL  the two targets diverged at assertion ${at}: ${J(lhs.names[at])} against ${J(rhs.names[at])}`);
      ok = false;
    }
  }

  if (!ok) {
    process.exit(1);
  }
  const where = results.length === 2
    ? `parse-rust and parse-server`
    : `${SERVER_URL} only (upstream half not requested)`;
  const regime = DETAILED
    ? 'enableSanitizedErrorResponse=false'
    : 'enableSanitizedErrorResponse default (true)';
  console.log(`OK  authorization [${regime}]: ${results[0].names.length} assertions pass against ${where}`);
  process.exit(0);
}

main().catch(e => {
  // The stack, not just the message. A case that throws outside an assertion is a harness bug or
  // an unexpected server refusal, and "Object not found." on its own does not say which call.
  console.error('harness error:', e && e.stack ? e.stack : e);
  process.exit(2);
});
