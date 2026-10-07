/*
 * Gate E of the 0.2.1 milestone, and Gate I of 0.3.0, in one runner because both boot the same
 * four servers and compare them.
 *
 * Gate E: three authorization decisions at stock server configuration.
 *
 * 0.2.0 shipped all three open, and all three are reachable on a deployment nobody has configured:
 *
 *   - `masterKeyIps` was unimplemented, so the master key was honoured from any source address.
 *     Upstream defaults it to `['127.0.0.1', '::1']`, so a stock parse-server honours the master
 *     key only from the machine it runs on.
 *   - A `_User` signed up with an `ACL` of `null`, `false`, `0`, `""` or `{"__op":"Delete"}` was
 *     created world-readable instead of owner-only. The other object-shaped values, an array, a
 *     tagged value and a non-`Delete` operation, were master-only rather than public: still wrong,
 *     because the owner was missing, but not a disclosure.
 *   - A CLP-declared default ACL was accepted, stored, echoed by `GET /schemas` and never applied,
 *     so a class configured as private created world-readable rows.
 *
 * **This gate boots its own servers rather than taking one from `with_server`**, because both
 * halves need to vary server configuration and the master-key half needs a second source address.
 * Four servers: parse-rust and parse-server, each at the default and each with the second peer
 * added to `masterKeyIps`.
 *
 * **Every assertion has a control that a broken server would fail.** All of these are passable by
 * an outage: "the master key is refused" passes if the master key never works, and "user B cannot
 * read the object" passes if reads never work. So each refusal is paired with the same request
 * succeeding somewhere it should.
 *
 * **The second peer address is a requirement, not an implementation detail.** The shipped defect
 * is a *remote* caller accepted at the *default* configuration, and a gate that only ever speaks
 * from `127.0.0.1` never sends that request. Two ways to get one, in order of preference:
 *
 *   1. `127.0.0.2` as the client's source address. Not in the default allowlist, which is the two
 *      literal addresses rather than a range. Works out of the box on Linux, and exposes nothing:
 *      the servers stay bound to loopback. On macOS it needs `sudo ifconfig lo0 alias 127.0.0.2`.
 *   2. The machine's own non-loopback IPv4. The servers then bind `0.0.0.0` and are briefly
 *      reachable from the local network on an ephemeral port. The run says so out loud.
 *
 * With neither available the gate fails rather than skipping, and names the one-line fix.
 *
 * Every assertion here holds against parse-server, so a failure means parse-rust diverged.
 *
 * Usage:
 *   node tools/spec/stock-config.mjs <mongo-uri> [appId] [masterKey]
 */

import http from 'node:http';
import net from 'node:net';
import os from 'node:os';
import path from 'node:path';
import { spawn } from 'node:child_process';
import { createRequire } from 'node:module';
import { fileURLToPath } from 'node:url';

const require = createRequire(import.meta.url);
const REPO = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..');
const PS_ROOT = path.resolve(REPO, process.env.PARSE_SERVER_ROOT || '../parse-server');
const { ParseServer } = require(`${PS_ROOT}/lib/index.js`);
// The driver upstream itself depends on, so the two servers and this runner agree on one version.
// Several Gate I conditions are about what is stored, which no response shows.
const { MongoClient } = require(`${PS_ROOT}/node_modules/mongodb`);

const [, , MONGO_URI, APP_ID = 'test', MASTER_KEY = 'test'] = process.argv;
if (!MONGO_URI) {
  console.error('usage: node tools/spec/stock-config.mjs <mongo-uri> [appId] [masterKey]');
  process.exit(2);
}

/*
 * **Per-section inventories, not one total.** A single floor over the whole run is satisfiable by
 * the wrong half: the first version of this file set one floor of 44 against 60 assertions, split
 * 16 master-key and 44 ACL, so deleting the entire master-key half left exactly 44 and reported
 * green. A floor that a deleted subject can still clear is not a floor.
 *
 * Exact counts rather than minimums, so adding an assertion is a deliberate edit here too. Each
 * number is the **total across both servers**, since every section runs against each of them.
 */
const EXPECTED = {
  'master key': 16,
  'default ACL': 104,
  'user identity': 40,
  'custom objectId': 20,
  'I1 explain': 30,
  'I2 lockout': 18,
  'I3 installation': 16,
  'I4 limit': 20,
  'I5-6 user ACL refusals': 24,
  'I7 ACL arrays': 16,
  'I8 permission order': 4,
  'I9 objectId operation': 3,
  'I10 user update authorization': 24,
  'I11 ACL operations': 28,
};

const TAG = `${process.pid}x${Date.now().toString(36)}`;
// Gate I condition 2. A short duration, so the run does not have to wait out a real lock.
const LOCKOUT = { duration: 5, threshold: 2 };
let mongo = null;
const PASSWORD = 'correct horse battery staple';

let passed = 0;
let section = '(setup)';
const counts = new Map();
const failures = [];
const J = v => JSON.stringify(v);

function enter(name) { section = name; }

function check(name, cond, detail = '') {
  if (cond) {
    passed++;
    counts.set(section, (counts.get(section) ?? 0) + 1);
  } else {
    failures.push(`[${section}] ${name}${detail ? `: ${detail}` : ''}`);
  }
}
function eq(name, actual, expected) {
  check(name, actual === expected, `expected ${J(expected)}, got ${J(actual)}`);
}

// -------------------------------------------------------------------------------------------
// The second peer address
// -------------------------------------------------------------------------------------------

/** Can a client socket bind this source address? */
function canBindSource(address) {
  return new Promise(resolve => {
    const probe = net.createServer();
    probe.once('error', () => resolve(false));
    probe.listen(0, address, () => probe.close(() => resolve(true)));
  });
}

async function chooseSecondPeer() {
  if (await canBindSource('127.0.0.2')) {
    return { peer: '127.0.0.2', bind: '127.0.0.1', connectHost: '127.0.0.1', exposed: false };
  }
  const lan = Object.values(os.networkInterfaces()).flat()
    .find(a => a && a.family === 'IPv4' && !a.internal);
  if (lan) {
    return { peer: lan.address, bind: '0.0.0.0', connectHost: lan.address, exposed: true };
  }
  console.error(
    'gate E needs a second source address and found neither.\n' +
    '  fix (macOS):  sudo ifconfig lo0 alias 127.0.0.2\n' +
    '  fix (Linux):  127.0.0.0/8 is local already; check that loopback is up\n' +
    'Refusing to run from 127.0.0.1 alone: the defect under test is a remote peer at the default\n' +
    'configuration, and a run that never produces one would report green having tested nothing.',
  );
  process.exit(1);
}

// -------------------------------------------------------------------------------------------
// Raw HTTP, because the subject is the source address and the headers
// -------------------------------------------------------------------------------------------

/**
 * One request. `from` is `'loopback'` or `'peer'`, which is the whole point of this gate; the SDK
 * offers no way to choose.
 *
 * **The destination address travels with the source and cannot be picked independently.** When the
 * second peer is a real interface address, a socket cannot bind a loopback source and route to it,
 * so the loopback requests must go to `127.0.0.1` while the peer requests go to the interface. The
 * servers bind `0.0.0.0` in that case precisely so both destinations reach the same process. An
 * earlier draft used one destination for both and every loopback request died with ECONNRESET.
 */
function request(server, { method = 'GET', path: p, from, headers = {}, body, raw, appId }) {
  // `raw` is a body string sent exactly as written. Gate I condition 8 needs one, because an object
  // literal reorders integer-like keys before `JSON.stringify` sees them.
  const payload = raw !== undefined ? raw : body === undefined ? undefined : JSON.stringify(body);
  const all = {
    'X-Parse-Application-Id': appId ?? server.appId,
    ...(payload === undefined ? {} : { 'Content-Type': 'application/json' }),
    ...headers,
  };
  const route = from === 'peer' ? server.peerRoute : server.loopbackRoute;
  return new Promise((resolve, reject) => {
    const req = http.request({
      host: route.host,
      port: server.port,
      path: `/parse${p}`,
      method,
      localAddress: route.source,
      headers: all,
      // A fresh connection per request, never a pooled one. Node's global agent keeps sockets
      // alive, and a gate whose subject is the peer address of a connection must not reuse one:
      // a socket the server has since closed answers the next request with ECONNRESET, which
      // reads as a server bug rather than as pooling.
      agent: false,
    }, res => {
      let raw = '';
      res.on('data', c => { raw += c; });
      res.on('end', () => {
        let json = null;
        try { json = JSON.parse(raw); } catch { /* a non-JSON body is a result too */ }
        resolve({ status: res.statusCode, body: json, raw });
      });
    });
    // Named, because a bare ECONNRESET says nothing about which of four servers, which source
    // address and which route produced it, and this gate has three of each in play.
    req.on('error', e => reject(new Error(
      `${method} ${p} to ${server.kind}@${route.host}:${server.port} from ${route.source}: ${e.message}`,
      { cause: e },
    )));
    if (payload !== undefined) { req.write(payload); }
    req.end();
  });
}

const master = extra => ({ 'X-Parse-Master-Key': MASTER_KEY, ...extra });

// -------------------------------------------------------------------------------------------
// Booting
// -------------------------------------------------------------------------------------------

/** parse-rust, out of `target/debug`, reporting its bound address on stdout. */
function bootRust(bind, env) {
  return new Promise((resolve, reject) => {
    const child = spawn(path.join(REPO, 'target/debug/parse-rust'), [], {
      cwd: REPO,
      env: {
        ...process.env,
        PARSE_SERVER_APPLICATION_ID: APP_ID,
        PARSE_SERVER_MASTER_KEY: MASTER_KEY,
        PARSE_SERVER_ALLOW_CLIENT_CLASS_CREATION: 'true',
        PARSE_SERVER_MOUNT_PATH: '/parse',
        PARSE_SERVER_HOST: bind,
        PARSE_SERVER_DATABASE_URI: MONGO_URI,
        PORT: '0',
        ...env,
      },
    });
    let log = '';
    const timer = setTimeout(() => {
      child.kill();
      reject(new Error(`parse-rust never reported a bound address:\n${log}`));
    }, 20000);
    child.stdout.on('data', chunk => {
      log += chunk;
      const m = /^parse-rust listening on http:\/\/([^\s]+)$/m.exec(log);
      if (!m) { return; }
      clearTimeout(timer);
      const [, hostPort] = m;
      const port = Number(hostPort.split(':').pop());
      resolve({ kind: 'parse-rust', appId: APP_ID, port, child });
    });
    child.stderr.on('data', chunk => { log += chunk; });
    child.on('exit', code => {
      clearTimeout(timer);
      reject(new Error(`parse-rust exited with ${code}:\n${log}`));
    });
  });
}

/**
 * parse-server.
 *
 * **A distinct appId per instance**, because `Config` is a process-global keyed by appId: two
 * instances sharing one would leave the second's options answering the first's requests, and the
 * default-configuration server would quietly be the configured one.
 */
async function bootUpstream(bind, appId, extra) {
  const instance = await ParseServer.startApp({
    appId,
    masterKey: MASTER_KEY,
    databaseURI: MONGO_URI,
    serverURL: `http://127.0.0.1/parse`,
    mountPath: '/parse',
    host: bind,
    port: 0,
    silent: true,
    allowClientClassCreation: true,
    // Off, or `startApp` replaces the SDK's REST controller with an in-process router and the
    // requests never touch a socket. This gate is about the socket.
    directAccess: false,
    ...extra,
  });
  return {
    kind: 'parse-server',
    appId,
    port: instance.server.address().port,
    close: () => new Promise(done => instance.server.close(done)),
  };
}

// -------------------------------------------------------------------------------------------

async function main() {
  const { peer, bind, connectHost, exposed } = await chooseSecondPeer();
  console.log(`gate E: second peer ${peer}, servers bound to ${bind}`);
  if (exposed) {
    console.log(
      '  note: no loopback alias was available, so the servers are briefly reachable from the\n' +
      '        local network on ephemeral ports. `sudo ifconfig lo0 alias 127.0.0.2` avoids it.',
    );
  }

  const allowlist = ['127.0.0.1', '::1', peer].join(',');
  const servers = {};
  const started = [];

  // **Registered as each one starts, not after all four have.** A failure on the third boot used
  // to leave the first two running, and this script kills the whole group in `finally`, so the
  // orphans outlived the run holding ports and a database.
  const start = async (key, boot) => {
    const s = await boot();
    s.loopbackRoute = { host: '127.0.0.1', source: '127.0.0.1' };
    s.peerRoute = { host: connectHost, source: peer };
    started.push(s);
    servers[key] = s;
  };

  try {
    await start('rustDefault', () => bootRust(bind, {}));
    // The configured pair also enables `allowCustomObjectId`, which the objectId condition needs
    // and which nothing else in this gate reads. Reusing it beats booting a fifth and sixth server.
    // Gate I adds `accountLockout` to the configured pair. Nothing else on it fails a login.
    await start('rustConfigured', () => bootRust(bind, {
      PARSE_SERVER_MASTER_KEY_IPS: allowlist,
      PARSE_SERVER_ALLOW_CUSTOM_OBJECT_ID: 'true',
      PARSE_SERVER_ACCOUNT_LOCKOUT: JSON.stringify(LOCKOUT),
    }));
    await start('upstreamDefault', () => bootUpstream(bind, `${APP_ID}_d_${TAG}`, {}));
    await start('upstreamConfigured', () => bootUpstream(bind, `${APP_ID}_c_${TAG}`, {
      masterKeyIps: ['127.0.0.1', '::1', peer],
      allowCustomObjectId: true,
      accountLockout: LOCKOUT,
    }));

    await masterKeySourceAddress(servers, peer);
    await declaredDefaultAcl([servers.rustDefault, servers.upstreamDefault]);
    await userIdentity([servers.rustDefault, servers.upstreamDefault]);
    await customObjectId([servers.rustConfigured, servers.upstreamConfigured]);

    mongo = await MongoClient.connect(MONGO_URI);
    const defaults = [servers.rustDefault, servers.upstreamDefault];
    await gateI1Explain(defaults);
    await gateI2Lockout(servers.rustConfigured, servers.upstreamConfigured);
    await gateI3Installation(defaults);
    await gateI4Limit(defaults);
    await gateI5And6UserAclRefusals(defaults);
    await gateI7AclArrays(defaults);
    await gateI8PermissionOrder(defaults);
    await gateI9ObjectIdOperation([servers.rustConfigured, servers.upstreamConfigured]);
    await gateI10UserUpdateAuthorization(defaults);
    await gateI11AclOperations(defaults);
  } finally {
    if (mongo) { await mongo.close(); }
    for (const s of started) {
      if (s.child) { s.child.kill(); } else if (s.close) { await s.close(); }
    }
  }

  report();
}

// -------------------------------------------------------------------------------------------
// Conditions 1-5: the master key's source address
// -------------------------------------------------------------------------------------------

async function masterKeySourceAddress(servers, peer) {
  enter('master key');
  const pairs = [
    ['parse-rust', servers.rustDefault, servers.rustConfigured],
    ['parse-server', servers.upstreamDefault, servers.upstreamConfigured],
  ];

  for (const [who, atDefault, configured] of pairs) {
    // 1. The shipped defect. No other condition sends this request.
    const remote = await request(atDefault, { path: '/schemas', from: 'peer', headers: master() });
    eq(`${who}: a master key from ${peer} is refused at the default`, remote.status, 403);
    eq(`${who}: and refused as the bare envelope`, remote.body?.error, 'unauthorized');
    check(`${who}: with no Parse code`, remote.body?.code === undefined, `got ${J(remote.body)}`);

    // 2. The control for 1: the same request, with that address allowed.
    const allowed = await request(configured, { path: '/schemas', from: 'peer', headers: master() });
    eq(`${who}: the same request succeeds once ${peer} is in masterKeyIps`, allowed.status, 200);

    // 3. The control for the default itself: refusing everything would satisfy 1.
    const loopback = await request(atDefault, {
      path: '/schemas', from: 'loopback', headers: master(),
    });
    eq(`${who}: the master key still works from 127.0.0.1 at the default`, loopback.status, 200);

    // 4. The forgery case. A client-supplied header must not admit a non-allowlisted peer.
    for (const header of ['X-Forwarded-For', 'X-Real-IP']) {
      const forged = await request(atDefault, {
        path: '/schemas', from: 'peer', headers: master({ [header]: '127.0.0.1' }),
      });
      eq(`${who}: ${header} claiming 127.0.0.1 does not admit ${peer}`, forged.status, 403);
    }

    // 5. The converse, so the header is inert rather than inverted.
    const inert = await request(atDefault, {
      path: '/schemas', from: 'loopback', headers: master({ 'X-Forwarded-For': peer }),
    });
    eq(`${who}: and does not evict an allowlisted caller`, inert.status, 200);
  }
}

// -------------------------------------------------------------------------------------------
// Conditions 6-11: the CLP-declared default ACL
//
// Every assertion is a read or a write, never a look at `_rperm`. The failure being guarded is
// that no permission columns are written at all, and a test that inspects a column and finds it
// absent has to decide what absent means. A request does not.
// -------------------------------------------------------------------------------------------

/**
 * The operations, all open.
 *
 * **Spelled out because a present `classLevelPermissions` block is merged over `emptyCLPS`**, so
 * an operation the block does not name grants nobody. A class declaring only an `ACL` key would be
 * unreachable through the CLP gate, and every assertion below would pass because nothing could be
 * created rather than because the default ACL was applied.
 */
const OPEN = {
  find: { '*': true }, count: { '*': true }, get: { '*': true }, create: { '*': true },
  update: { '*': true }, delete: { '*': true }, addField: { '*': true },
};

async function declareClass(server, className, acl) {
  const created = await request(server, {
    method: 'POST', path: '/schemas', from: 'loopback', headers: master(),
    body: {
      className,
      fields: { title: { type: 'String' } },
      classLevelPermissions: acl ? { ...OPEN, ACL: acl } : OPEN,
    },
  });
  eq(`${server.kind}: declared ${className}`, created.status, 200);
}

async function signUp(server, name) {
  const created = await request(server, {
    method: 'POST', path: '/users', from: 'loopback',
    body: { username: `${name}_${TAG}_${server.kind}`, password: PASSWORD },
  });
  eq(`${server.kind}: signed up ${name}`, created.status, 201);
  return { id: created.body?.objectId, token: created.body?.sessionToken };
}

const as = token => ({ 'X-Parse-Session-Token': token });

async function findAll(server, className, token) {
  const found = await request(server, {
    path: `/classes/${className}`, from: 'loopback', headers: as(token),
  });
  eq(`${server.kind}: ${className} is queryable`, found.status, 200);
  return found.body?.results ?? [];
}

async function declaredDefaultAcl(servers) {
  enter('default ACL');
  for (const server of servers) {
    const who = server.kind;
    // **Per-server class names.** Both servers run against one database, which is what makes the
    // two halves comparable, and a shared class name would make the second server's `POST
    // /schemas` fail with "class already exists" and its control count the first server's rows.
    // No hyphen: upstream's class-name grammar is `[A-Za-z][A-Za-z0-9_]*`.
    const suffix = `${TAG}_${server.kind === 'parse-rust' ? 'rust' : 'upstream'}`;
    const Private = `E1_${suffix}`;
    const Open = `E2_${suffix}`;
    const Shared = `E3_${suffix}`;
    await declareClass(server, Private, { currentUser: { read: true, write: true } });
    await declareClass(server, Open, null);
    await declareClass(server, Shared, { currentUser: { read: true, write: true } });

    const a = await signUp(server, 'e_owner');
    const b = await signUp(server, 'e_stranger');

    // 6. A creates an object in the private class.
    const created = await request(server, {
      method: 'POST', path: `/classes/${Private}`, from: 'loopback',
      headers: as(a.token), body: { title: 'x' },
    });
    eq(`${who}: A creates an object in a class declared private`, created.status, 201);
    const id = created.body?.objectId;

    // 6b. **The create response carries the resolved ACL.** It is the only way the caller learns
    //     what permissions its object got, because on a private class it cannot read the row back
    //     to find out. Upstream marks the field server-changed and returns it
    //     (`RestWrite.js:454`). Every other condition here inspects a later request, so all of
    //     them pass against a server that says nothing in the response.
    eq(`${who}: the create response names the ACL it generated`,
      J(created.body?.ACL), J({ [a.id]: { read: true, write: true } }));

    // 6c. An anonymous create has no id to substitute for `currentUser`, and upstream's `delete`
    //     runs anyway, so the response is an empty ACL rather than no ACL key.
    const orphan = await request(server, {
      method: 'POST', path: `/classes/${Private}`, from: 'loopback', body: { title: 'anon' },
    });
    eq(`${who}: an anonymous create succeeds`, orphan.status, 201);
    eq(`${who}: and answers an empty ACL rather than omitting the key`, J(orphan.body?.ACL), J({}));

    // 7. A is not locked out. This is the half an empty ACL, or one storing the literal string
    //    `currentUser`, would fail while still passing condition 8.
    const mine = await findAll(server, Private, a.token);
    eq(`${who}: A can read its own object`, mine.length, 1);
    const mineUpdated = await request(server, {
      method: 'PUT', path: `/classes/${Private}/${id}`, from: 'loopback',
      headers: as(a.token), body: { title: 'y' },
    });
    eq(`${who}: A can write it too`, mineUpdated.status, 200);

    // 8. B can do neither. Write as well as read, because `_wperm` and `_rperm` are written
    //    separately and one can be right while the other is absent.
    eq(`${who}: B cannot read it`, (await findAll(server, Private, b.token)).length, 0);
    const denied = await request(server, {
      method: 'PUT', path: `/classes/${Private}/${id}`, from: 'loopback',
      headers: as(b.token), body: { title: 'z' },
    });
    eq(`${who}: B cannot write it`, denied.status, 404);
    eq(`${who}: and is told only that it does not exist`, denied.body?.code, 101);

    // 9. The control. Without it, 7 and 8 pass against a server that cannot read anything.
    const inOpen = await request(server, {
      method: 'POST', path: `/classes/${Open}`, from: 'loopback',
      headers: as(a.token), body: { title: 'x' },
    });
    eq(`${who}: A creates an object in a class with no declared ACL`, inOpen.status, 201);
    eq(`${who}: B can read that one`, (await findAll(server, Open, b.token)).length, 1);

    // 10. The `!this.query` guard. A server that stamps the default on every write passes
    //     everything above while silently reverting a permission a client set on purpose.
    const shared = await request(server, {
      method: 'POST', path: `/classes/${Shared}`, from: 'loopback', headers: as(a.token),
      body: {
        title: 'x',
        ACL: { [a.id]: { read: true, write: true }, [b.id]: { read: true } },
      },
    });
    eq(`${who}: A creates an object carrying its own ACL`, shared.status, 201);
    eq(`${who}: the client's ACL wins over the class default`,
      (await findAll(server, Shared, b.token)).length, 1);

    const touched = await request(server, {
      method: 'PUT', path: `/classes/${Shared}/${shared.body?.objectId}`, from: 'loopback',
      headers: as(a.token), body: { title: 'y' },
    });
    eq(`${who}: an unrelated update succeeds`, touched.status, 200);
    eq(`${who}: and does not restamp the class default over the ACL`,
      (await findAll(server, Shared, b.token)).length, 1);

    // 11. **A falsy `ACL` on signup is "no ACL", not "leave it alone".** Upstream's test is
    //     `if (!ACL)` (`RestWrite.js:1815-1825`), so all four falsy values produce the owner-only
    //     ACL that an absent one produces. 0.2.0 left them in place, `lower_acl` then dropped them
    //     without writing permission columns, and an absent `_rperm` is public: the `_User` row was
    //     readable by every anonymous caller. This is a third stock-configuration failure and it
    //     lives with the other two.
    //
    //     All four are sent rather than one, because checking one is how the other three survived.
    for (const [label, value] of [['null', null], ['false', false], ['0', 0], ['""', '']]) {
      const signup = await request(server, {
        method: 'POST', path: '/users', from: 'loopback',
        body: { username: `e_falsy_${label.replace(/\W/g, '')}_${suffix}`, password: PASSWORD, ACL: value },
      });
      eq(`${who}: signup with ACL:${label} succeeds`, signup.status, 201);
      const anon = await request(server, {
        method: 'GET', path: `/classes/_User/${signup.body?.objectId}`, from: 'loopback',
      });
      eq(`${who}: and the user is not publicly readable with ACL:${label}`, anon.status, 404);
      const owner = await request(server, {
        method: 'GET', path: `/classes/_User/${signup.body?.objectId}`, from: 'loopback',
        headers: master(),
      });
      eq(`${who}: the owner entry is present with ACL:${label}`,
        J(owner.body?.ACL), J({ [signup.body?.objectId]: { read: true, write: true } }));
    }

    // 12. **The shapes that are objects in JavaScript and are not `ParseValue::Object` here.**
    //     An op envelope, an array and a tagged value all reach upstream's
    //     `ACL[objectId] = {read, write}` as objects and come back owner-only, because none of
    //     their keys carries a `read` or a `write`. Matching only on the object case skipped them,
    //     and `{"__op":"Delete"}` was then removed from the body entirely, leaving a **publicly
    //     readable `_User`**. The falsy loop above does not reach any of these.
    for (const [label, value] of [
      ['op-Delete', { __op: 'Delete' }],
      ['array', [1, 2]],
      ['tagged-Date', { __type: 'Date', iso: '2020-01-01T00:00:00.000Z' }],
    ]) {
      const signup = await request(server, {
        method: 'POST', path: '/users', from: 'loopback',
        body: { username: `e_shape_${label.replace(/\W/g, '')}_${suffix}`, password: PASSWORD, ACL: value },
      });
      eq(`${who}: signup with ACL ${label} succeeds`, signup.status, 201);
      const anon = await request(server, {
        method: 'GET', path: `/classes/_User/${signup.body?.objectId}`, from: 'loopback',
      });
      eq(`${who}: and the user is not publicly readable with ACL ${label}`, anon.status, 404);
      const owner = await request(server, {
        method: 'GET', path: `/classes/_User/${signup.body?.objectId}`, from: 'loopback',
        headers: master(),
      });
      eq(`${who}: the owner entry is present with ACL ${label}`,
        J(owner.body?.ACL), J({ [signup.body?.objectId]: { read: true, write: true } }));
    }

    // 13. The same root cause on an ordinary class, where the answer is different: upstream keeps
    //     the op object, `transformObjectACL` finds no permission in it, and two **empty** arrays
    //     are written, which is master-only. Here the op was stripped and no columns were written
    //     at all, which is public. Asserted through a read, so "master-only" shows up as the
    //     anonymous 404 that the empty columns produce.
    const opAcl = await request(server, {
      method: 'POST', path: `/classes/${Open}`, from: 'loopback',
      headers: as(a.token), body: { title: 'x', ACL: { __op: 'Delete' } },
    });
    eq(`${who}: a create carrying an ACL operation succeeds`, opAcl.status, 201);
    const opAnon = await request(server, {
      method: 'GET', path: `/classes/${Open}/${opAcl.body?.objectId}`, from: 'loopback',
    });
    eq(`${who}: and the object is not publicly readable`, opAnon.status, 404);
    // The control, on the same class: an ordinary create with no ACL **is** public, so the
    // assertion above is the operation rather than the class.
    const plainObject = await request(server, {
      method: 'POST', path: `/classes/${Open}`, from: 'loopback',
      headers: as(a.token), body: { title: 'y' },
    });
    eq(`${who}: a create with no ACL succeeds`, plainObject.status, 201);
    const plainObjectAnon = await request(server, {
      method: 'GET', path: `/classes/${Open}/${plainObject.body?.objectId}`, from: 'loopback',
    });
    eq(`${who}: and that one is publicly readable`, plainObjectAnon.status, 200);

    // The control for the block above: a signup that sends no ACL at all is readable by nobody
    // either, so those twelve assertions are about the falsy values rather than about signup.
    const plain = await request(server, {
      method: 'POST', path: '/users', from: 'loopback',
      body: { username: `e_plain_${suffix}`, password: PASSWORD },
    });
    eq(`${who}: a signup with no ACL succeeds`, plain.status, 201);
    const plainAnon = await request(server, {
      method: 'GET', path: `/classes/_User/${plain.body?.objectId}`, from: 'loopback',
    });
    eq(`${who}: and is private too`, plainAnon.status, 404);
  }
}

// -------------------------------------------------------------------------------------------
// A `_User` update must never remove its owner's own access
//
// The failure here is the opposite of the rest of this gate: not disclosure but denial. A `_User`
// whose permission columns come back empty is a row its owner can no longer read, write or log in
// with, and any principal permitted to write that row could do it. Upstream forces the owner entry
// back in for every non-privileged update carrying a truthy `ACL` (`RestWrite.js:1729-1738`), and
// parse-rust handled a principal map and `{"__op":"Delete"}` and nothing else.
// -------------------------------------------------------------------------------------------

async function userIdentity(servers) {
  enter('user identity');
  for (const server of servers) {
    const who = server.kind;
    const suffix = `${TAG}_${server.kind === 'parse-rust' ? 'rust' : 'upstream'}`;

    for (const [label, value] of [
      ['op-Increment', { __op: 'Increment', amount: 1 }],
      ['op-Delete', { __op: 'Delete' }],
      ['array', [1, 2]],
      ['tagged-Date', { __type: 'Date', iso: '2020-01-01T00:00:00.000Z' }],
      // **A truthy scalar is deliberately not here.** Upstream answers 500 to that update and
      // parse-rust 400, a chosen difference that Gate I condition 6 asserts per server.
    ]) {
      const u = await signUp(server, `ui_${label.replace(/\W/g, '')}`);
      const updated = await request(server, {
        method: 'PUT', path: `/classes/_User/${u.id}`, from: 'loopback',
        headers: as(u.token), body: { ACL: value },
      });
      eq(`${who}: an update carrying ACL ${label} succeeds`, updated.status, 200);
      // The assertion that matters is not the stored shape, it is whether the account still
      // works: the session the caller already holds must keep resolving.
      const me = await request(server, {
        method: 'GET', path: '/users/me', from: 'loopback', headers: as(u.token),
      });
      eq(`${who}: and the owner is not locked out by ACL ${label}`, me.status, 200);
      const owner = await request(server, {
        method: 'GET', path: `/classes/_User/${u.id}`, from: 'loopback', headers: master(),
      });
      eq(`${who}: the owner entry survives ACL ${label}`,
        J(owner.body?.ACL?.[u.id]), J({ read: true, write: true }));
    }

    // The control, and the half that must not change: a **falsy** ACL on an update leaves the
    // stored columns alone rather than acquiring an owner-only ACL, because upstream's test is
    // `this.data.ACL &&`. Without this, "always force an owner in" passes everything above and
    // silently replaces a deliberate ACL on any request that sends `ACL: null`.
    const keep = await signUp(server, 'ui_falsy');
    const shared = await request(server, {
      method: 'PUT', path: `/classes/_User/${keep.id}`, from: 'loopback', headers: as(keep.token),
      body: { ACL: { [keep.id]: { read: true, write: true }, '*': { read: true } } },
    });
    eq(`${who}: an explicit ACL is accepted`, shared.status, 200);
    const nulled = await request(server, {
      method: 'PUT', path: `/classes/_User/${keep.id}`, from: 'loopback', headers: as(keep.token),
      body: { ACL: null },
    });
    eq(`${who}: a falsy ACL on an update succeeds`, nulled.status, 200);
    const after = await request(server, {
      method: 'GET', path: `/classes/_User/${keep.id}`, from: 'loopback', headers: master(),
    });
    eq(`${who}: and leaves the stored ACL alone`,
      J(after.body?.ACL), J({ [keep.id]: { read: true, write: true }, '*': { read: true } }));
  }
}

// -------------------------------------------------------------------------------------------
// A truthy non-string objectId is refused rather than replaced
//
// Runs against the pair configured with `allowCustomObjectId`, because at the default both servers
// refuse a client-supplied id outright and the condition would pass without exercising anything.
// -------------------------------------------------------------------------------------------

async function customObjectId(servers) {
  enter('custom objectId');
  for (const server of servers) {
    const who = server.kind;
    const suffix = `${TAG}_${server.kind === 'parse-rust' ? 'rust' : 'upstream'}`;

    // A string id is honoured, which is the whole point of the option and the control for below.
    const chosen = `custom${suffix}`.replace(/\W/g, '').slice(0, 30);
    const ok = await request(server, {
      method: 'POST', path: '/users', from: 'loopback',
      body: { objectId: chosen, username: `cid_ok_${suffix}`, password: PASSWORD },
    });
    eq(`${who}: a string objectId is accepted`, ok.status, 201);
    eq(`${who}: and is the id the client asked for`, ok.body?.objectId, chosen);

    // A truthy non-string is a type error, not an absent id.
    for (const [label, value] of [['number', 123], ['boolean', true]]) {
      const refused = await request(server, {
        method: 'POST', path: '/users', from: 'loopback',
        body: { objectId: value, username: `cid_${label}_${suffix}`, password: PASSWORD },
      });
      eq(`${who}: a ${label} objectId is refused`, refused.status, 400);
      eq(`${who}: as INCORRECT_TYPE`, refused.body?.code, 111);
      // And nothing was written, so the username is still free. parse-rust answered 201 and
      // persisted a user under a generated id, which consumed it.
      const retry = await request(server, {
        method: 'POST', path: '/users', from: 'loopback',
        body: { username: `cid_${label}_${suffix}`, password: PASSWORD },
      });
      eq(`${who}: and the username was not consumed by the refusal`, retry.status, 201);
    }

    // An entry under the caller's own custom id is replaced by the owner before the SDK judges it
    // when the body has no email (`RestWrite.js:1824` before `:1149`), and judged first when it does
    // (`:1013`). So the same malformed owner entry is accepted without an email and refused with one.
    for (const withEmail of [false, true]) {
      const id = `own${withEmail ? 'e' : 'n'}${suffix}`.replace(/\W/g, '').slice(0, 30);
      const body = {
        objectId: id, username: `cid_own_${withEmail ? 'e' : 'n'}_${suffix}`, password: PASSWORD,
        ACL: { [id]: { read: 1 } },
      };
      if (withEmail) { body.email = `${body.username}@example.com`; }
      const r = await request(server, { method: 'POST', path: '/users', from: 'loopback', body });
      eq(`${who}: a malformed entry under the new user's own id, ${withEmail ? 'with' : 'without'} an email`,
        r.status, withEmail ? 500 : 201);
    }
  }
}

// ===========================================================================================
// Gate I of 0.3.0: the security defaults and the parity closures, two servers compared.
//
// **Several conditions assert a recorded difference rather than agreement**, and each says so: the
// `ACL` refusals parse-rust makes before an insert, the truthy-scalar choice, and the operation as
// an `objectId`. `CHANGELOG.md` lists them as deliberate differences; an assertion here that expects the same
// answer from both would be encoding a behavior the milestone chose not to reproduce.
// ===========================================================================================

const isRust = server => server.kind === 'parse-rust';
const suffixOf = server => `${TAG}_${isRust(server) ? 'rust' : 'upstream'}`;
const stored = (collection, filter) => mongo.db().collection(collection).findOne(filter);

// -------------------------------------------------------------------------------------------
// I1. `explain` requires the master key at the default configuration
// -------------------------------------------------------------------------------------------

async function gateI1Explain(servers) {
  enter('I1 explain');
  for (const server of servers) {
    const who = server.kind;
    const cls = `I1_${suffixOf(server)}`;
    const made = await request(server, {
      method: 'POST', path: `/classes/${cls}`, from: 'loopback', headers: master(), body: { n: 1 },
    });
    eq(`${who}: an object to explain`, made.status, 201);

    // The boundary. `databaseOptions.allowPublicExplain` defaults to false.
    for (const value of ['true', 'queryPlanner']) {
      const anon = await request(server, { path: `/classes/${cls}?explain=${value}`, from: 'loopback' });
      eq(`${who}: an anonymous explain=${value} is refused`, anon.status, 400);
      eq(`${who}: as INVALID_QUERY`, anon.body?.code, 102);
      eq(`${who}: naming the master key`, anon.body?.error,
        'Using the explain query parameter requires the master key');
    }
    // The control: the master key gets the database's document, not rows.
    const explained = await request(server, {
      path: `/classes/${cls}?explain=true`, from: 'loopback', headers: master(),
    });
    eq(`${who}: the master key may explain`, explained.status, 200);
    check(`${who}: and gets a plan rather than rows`,
      explained.body?.results && !Array.isArray(explained.body.results)
        && 'queryPlanner' in explained.body.results, J(explained.body).slice(0, 200));
    const bogus = await request(server, {
      path: `/classes/${cls}?explain=bogus`, from: 'loopback', headers: master(),
    });
    eq(`${who}: an unknown verbosity is refused`, bogus.body?.code, 102);
    eq(`${who}: by name`, bogus.body?.error, 'Invalid value for explain');
    // And the same query without explain is an ordinary read, so the refusal is the parameter's.
    const plain = await request(server, { path: `/classes/${cls}`, from: 'loopback' });
    eq(`${who}: the query itself is public`, plain.body?.results?.length, 1);

    // `$text` under explain on a class that has never been searched: the explain runs through the
    // same find path, which builds the text index first, so the database has one to plan with.
    const fresh = `I1t_${suffixOf(server)}`;
    await request(server, {
      method: 'POST', path: `/classes/${fresh}`, from: 'loopback', headers: master(), body: { subject: 'hello' },
    });
    const where = encodeURIComponent(JSON.stringify({ subject: { $text: { $search: { $term: 'hello' } } } }));
    const textExplain = await request(server, {
      path: `/classes/${fresh}?explain=true&where=${where}`, from: 'loopback', headers: master(),
    });
    eq(`${who}: explaining a first $text search answers 200`, textExplain.status, 200);

    const badPoint = encodeURIComponent(JSON.stringify({ location: { $geoWithin: { $polygon: [
      { __type: 'GeoPoint', latitude: 100, longitude: 0 },
      { __type: 'GeoPoint', latitude: 0, longitude: 1 },
      { __type: 'GeoPoint', latitude: 1, longitude: 1 },
    ] } } }));
    // An invalid point is thrown while the query is built, before the read path's sanitizing
    // `.catch` exists upstream, so it is the bare 500 rather than the find's sanitized one.
    const geo = await request(server, { path: `/classes/${cls}?where=${badPoint}`, from: 'loopback' });
    eq(`${who}: an out-of-range polygon point is a 500`, geo.status, 500);
    eq(`${who}: with the bare internal error`, J(geo.body), J({ code: 1, message: 'Internal server error.' }));
  }
}

// -------------------------------------------------------------------------------------------
// I2. Account lockout, configured identically, counted across the fleet
//
// Both servers share one database, so this is the mixed-fleet condition: failures through one node
// must lock the account on the other. Both orders, because a counter only one side writes passes
// one order and fails the other.
// -------------------------------------------------------------------------------------------

async function gateI2Lockout(rust, upstream) {
  enter('I2 lockout');
  const login = (server, username, password) => request(server, {
    method: 'POST', path: '/login', from: 'loopback', body: { username, password },
  });
  for (const [first, second] of [[rust, upstream], [upstream, rust]]) {
    const label = `${first.kind} then ${second.kind}`;
    const username = `i2_${isRust(first) ? 'r' : 'u'}_${TAG}`;
    const made = await request(first, {
      method: 'POST', path: '/users', from: 'loopback', body: { username, password: PASSWORD },
    });
    eq(`${label}: signed up`, made.status, 201);
    for (let i = 1; i <= LOCKOUT.threshold; i++) {
      const bad = await login(first, username, 'wrong');
      eq(`${label}: failure ${i} is an ordinary failure`, bad.body?.error, 'Invalid username/password.');
    }
    const row = await stored('_User', { username });
    eq(`${label}: the counter both nodes read`, row?._failed_login_count, LOCKOUT.threshold);
    check(`${label}: and the lock expiry is set`, row?._account_lockout_expires_at instanceof Date);
    const locked = await login(second, username, PASSWORD);
    eq(`${label}: the other node refuses the right password`, locked.status, 404);
    eq(`${label}: as locked`, locked.body?.error,
      `Your account is locked due to multiple failed login attempts. Please try again after ${LOCKOUT.duration} minute(s)`);
  }
  // The control: lockout is configured and an unlocked account still logs in on both.
  for (const server of [rust, upstream]) {
    const username = `i2_ok_${suffixOf(server)}`;
    await request(server, {
      method: 'POST', path: '/users', from: 'loopback', body: { username, password: PASSWORD },
    });
    const ok = await login(server, username, PASSWORD);
    eq(`${server.kind}: an unlocked account logs in`, ok.status, 200);
    eq(`${server.kind}: and a success leaves the counter at 0`,
      (await stored('_User', { username }))?._failed_login_count, 0);
  }
}

// -------------------------------------------------------------------------------------------
// I3. `_Installation` validation
// -------------------------------------------------------------------------------------------

async function gateI3Installation(servers) {
  enter('I3 installation');
  for (const server of servers) {
    const who = server.kind;
    const create = body => request(server, {
      method: 'POST', path: '/classes/_Installation', from: 'loopback', body,
    });
    const none = await create({ deviceType: 'ios' });
    eq(`${who}: no id is refused`, none.body?.code, 135);
    eq(`${who}: with upstream's message`, none.body?.error,
      'at least one ID field (deviceToken, installationId) must be specified in this operation');
    const noType = await create({ installationId: `i3-${suffixOf(server)}-a` });
    eq(`${who}: a create with no deviceType is refused`, noType.body?.code, 135);
    eq(`${who}: by name`, noType.body?.error, 'deviceType must be specified in this operation');
    const typed = await create({ deviceType: 'ios', deviceToken: { $ne: null } });
    eq(`${who}: an operator as deviceToken is a type error`, typed.body?.code, 111);
    // The control and the normalization. Distinct tokens per server, because upstream deduplicates
    // on the token across the shared database.
    const token = (isRust(server) ? 'ABCD' : 'EF01').repeat(16);
    const made = await create({ deviceType: 'ios', deviceToken: token, installationId: `I3-${suffixOf(server)}` });
    eq(`${who}: a valid installation is created`, made.status, 201);
    const row = await stored('_Installation', { _id: made.body?.objectId });
    eq(`${who}: a 64-character deviceToken is lowercased`, row?.deviceToken, token.toLowerCase());
    eq(`${who}: the installationId is lowercased`, row?.installationId, `i3-${suffixOf(server)}`.toLowerCase());
  }
}

// -------------------------------------------------------------------------------------------
// I4. A negative limit
// -------------------------------------------------------------------------------------------

async function gateI4Limit(servers) {
  enter('I4 limit');
  const counts = {};
  for (const server of servers) {
    const cls = `I4_${suffixOf(server)}`;
    for (let n = 0; n < 3; n++) {
      await request(server, { method: 'POST', path: `/classes/${cls}`, from: 'loopback', body: { n } });
    }
    counts[server.kind] = {};
    for (const limit of ['-1', '-2', '1.5', '0', 'abc', '[[2]]']) {
      const r = await request(server, { path: `/classes/${cls}?limit=${encodeURIComponent(limit)}`, from: 'loopback' });
      counts[server.kind][limit] = r.body?.results?.length;
    }
    // A count carries the request's `hint` to the database as the find does
    // (`DatabaseController.js:1525-1535`). An index that does not exist is the database's refusal,
    // which upstream's count path leaves uncaught; an index that does, counts. parse-rust dropped
    // the hint on a count and answered 200 to both.
    const countWith = hint => request(server, {
      path: `/classes/${cls}?limit=0&count=1&hint=${hint}&where=${encodeURIComponent('{"n":{"$gte":0}}')}`,
      from: 'loopback', headers: master(),
    });
    const missing = await countWith('nosuch');
    eq(`${server.kind}: a count hinting a missing index is refused`, missing.status, 500);
    eq(`${server.kind}: with the generic internal error`, J(missing.body), J({ code: 1, message: 'Internal server error.' }));
    const present = await countWith('_id_');
    eq(`${server.kind}: a count hinting an existing index answers`, present.status, 200);
    eq(`${server.kind}: and counts`, present.body?.count, 3);
  }
  // `[[2]]` is `Number(String([[2]]))`, which is 2: a nested array joins recursively.
  for (const [limit, expected] of [['-1', 1], ['-2', 2], ['1.5', 1], ['0', 0], ['abc', 3], ['[[2]]', 2]]) {
    for (const server of servers) {
      eq(`${server.kind}: limit=${limit} returns ${expected}`, counts[server.kind][limit], expected);
    }
  }
}

// -------------------------------------------------------------------------------------------
// I5 and I6. `ACL` values a signup refuses
// -------------------------------------------------------------------------------------------

async function gateI5And6UserAclRefusals(servers) {
  enter('I5-6 user ACL refusals');
  for (const server of servers) {
    const who = server.kind;
    for (const [label, acl] of [['an operation', { __op: 'Increment', amount: 1 }], ['a truthy scalar', 'nonsense']]) {
      for (const withEmail of [true, false]) {
        const username = `i5_${label.length}_${withEmail ? 'e' : 'n'}_${suffixOf(server)}`;
        const body = { username, password: PASSWORD, ACL: acl };
        if (withEmail) { body.email = `${username}@example.com`; }
        const r = await request(server, { method: 'POST', path: '/users', from: 'loopback', body });
        const branch = `${label}, ${withEmail ? 'with' : 'without'} an email`;
        // The response. Upstream's own answer splits on the email for a scalar; the choice made
        // for 0.3.0 is the 400 in both branches.
        const upstream500 = !isRust(server) && label === 'a truthy scalar' && !withEmail;
        eq(`${who}: ${branch} is refused`, r.status, upstream500 ? 500 : 400);
        eq(`${who}: ${branch} answers`, r.body?.code, upstream500 ? 1 : -1);
        // The state. Upstream inserts before it refuses an operation without an email; parse-rust
        // refuses before the insert in every branch, a recorded deliberate difference.
        const leavesRow = !isRust(server) && label === 'an operation' && !withEmail;
        eq(`${who}: ${branch} ${leavesRow ? 'leaves' : 'does not leave'} a row`,
          Boolean(await stored('_User', { username })), leavesRow);
      }
    }
  }
}

// -------------------------------------------------------------------------------------------
// I7. An `ACL` array grants the principals its indices name, on all three paths
// -------------------------------------------------------------------------------------------

async function gateI7AclArrays(servers) {
  enter('I7 ACL arrays');
  for (const server of servers) {
    const who = server.kind;
    const acl = [{ read: true }];
    const signup = await request(server, {
      method: 'POST', path: '/users', from: 'loopback',
      body: { username: `i7_s_${suffixOf(server)}`, password: PASSWORD, ACL: acl },
    });
    eq(`${who}: signup with an array ACL succeeds`, signup.status, 201);
    eq(`${who}: and grants index 0 beside the owner`,
      J((await stored('_User', { _id: signup.body?.objectId }))?._rperm), J(['0', signup.body?.objectId]));

    const u = await signUp(server, 'i7_u');
    const updated = await request(server, {
      method: 'PUT', path: `/classes/_User/${u.id}`, from: 'loopback', headers: as(u.token), body: { ACL: acl },
    });
    eq(`${who}: a _User update with an array ACL succeeds`, updated.status, 200);
    eq(`${who}: and grants index 0 beside the owner`,
      J((await stored('_User', { _id: u.id }))?._rperm), J(['0', u.id]));

    const cls = `I7_${suffixOf(server)}`;
    await declareClass(server, cls, acl);
    const made = await request(server, { method: 'POST', path: `/classes/${cls}`, from: 'loopback', body: { title: 'x' } });
    eq(`${who}: a create under an array default ACL succeeds`, made.status, 201);
    eq(`${who}: and grants index 0`, J((await stored(cls, { _id: made.body?.objectId }))?._rperm), J(['0']));
  }
}

// -------------------------------------------------------------------------------------------
// I8. Permission columns enumerate as JavaScript does
// -------------------------------------------------------------------------------------------

async function gateI8PermissionOrder(servers) {
  enter('I8 permission order');
  for (const server of servers) {
    const who = server.kind;
    const cls = `I8_${suffixOf(server)}`;
    // Hand-built, so the keys reach the server in this order. See `request`.
    const raw = '{"title":"x","ACL":{"zzz":{"read":true},"10":{"read":true},"2":{"read":true},"aaa":{"read":true}}}';
    const made = await request(server, { method: 'POST', path: `/classes/${cls}`, from: 'loopback', raw });
    eq(`${who}: created`, made.status, 201);
    eq(`${who}: array-index keys first, ascending, then insertion order`,
      J((await stored(cls, { _id: made.body?.objectId }))?._rperm), J(['2', '10', 'zzz', 'aaa']));
  }
}

// -------------------------------------------------------------------------------------------
// I9. An operation as `objectId`, under `allowCustomObjectId`. A recorded difference.
// -------------------------------------------------------------------------------------------

async function gateI9ObjectIdOperation(servers) {
  enter('I9 objectId operation');
  for (const server of servers) {
    const who = server.kind;
    const r = await request(server, {
      method: 'POST', path: '/users', from: 'loopback',
      body: { objectId: { __op: 'Delete' }, username: `i9_${suffixOf(server)}`, password: PASSWORD },
    });
    // Upstream accepts it and stores the row under an id nobody was told; parse-rust refuses, as
    // chosen in 0.3.0 section 7 (parse-community/parse-server#10639).
    eq(`${who}: ${isRust(server) ? 'refuses' : 'accepts'} an operation as objectId`,
      r.status, isRust(server) ? 400 : 201);
    if (isRust(server)) { eq(`${who}: as 107`, r.body?.code, 107); }
  }
}

// -------------------------------------------------------------------------------------------
// I10. A `_User` update is authorized before anything reads the target account
// -------------------------------------------------------------------------------------------

async function gateI10UserUpdateAuthorization(servers) {
  enter('I10 user update authorization');
  for (const server of servers) {
    const who = server.kind;
    const a = await signUp(server, 'i10_a');
    const b = await signUp(server, 'i10_b');
    const taken = `taken_${suffixOf(server)}`;
    await request(server, {
      method: 'POST', path: '/users', from: 'loopback',
      body: { username: taken, password: PASSWORD, email: `${taken}@example.com` },
    });
    const put = (id, body) => request(server, {
      method: 'PUT', path: `/classes/_User/${id}`, from: 'loopback', headers: as(a.token), body,
    });
    for (const [label, body] of [
      ['a taken username', { username: taken }],
      ['a free username', { username: `free_${suffixOf(server)}` }],
      ['a taken email', { email: `${taken}@example.com` }],
      ['a free email', { email: `free_${suffixOf(server)}@example.com` }],
      ['a retargeting objectId', { objectId: a.id, username: 'x' }],
    ]) {
      const r = await put(b.id, body);
      eq(`${who}: proposing ${label} for another user answers 206`, r.body?.code, 206);
    }
    // The controls: the checks still run for the owner, and for a row the caller may write.
    eq(`${who}: the owner proposing a taken username gets 202`, (await put(a.id, { username: taken })).body?.code, 202);
    await request(server, {
      method: 'PUT', path: `/classes/_User/${b.id}`, from: 'loopback', headers: master(),
      body: { ACL: { '*': { read: true, write: true } } },
    });
    eq(`${who}: a publicly writable row gets 202 too`, (await put(b.id, { username: taken })).body?.code, 202);

    // The owner still passes the class-level `update` gate before the uniqueness checks run
    // (`RestWrite.js:134` before `:144`). With `update` restricted to a role the caller lacks, every
    // proposal answers 119, taken or free, on both servers.
    const schemaPath = '/schemas/_User';
    const before = (await request(server, { method: 'GET', path: schemaPath, from: 'loopback', headers: master() })).body;
    const restricted = { ...before.classLevelPermissions, update: { 'role:I10Admins': true } };
    await request(server, {
      method: 'PUT', path: schemaPath, from: 'loopback', headers: master(),
      body: { classLevelPermissions: restricted },
    });
    for (const [label, body] of [
      ['a taken username', { username: taken }],
      ['a taken email', { email: `${taken}@example.com` }],
      ['a free username', { username: `free2_${suffixOf(server)}` }],
    ]) {
      eq(`${who}: under a restricted update CLP, the owner proposing ${label} answers 119`,
        (await put(a.id, body)).body?.code, 119);
    }
    await request(server, {
      method: 'PUT', path: schemaPath, from: 'loopback', headers: master(),
      body: { classLevelPermissions: before.classLevelPermissions },
    });
  }
}

// -------------------------------------------------------------------------------------------
// I11. An operation as `ACL` on an ordinary create, and the rest of `transformObjectACL`
// -------------------------------------------------------------------------------------------

async function gateI11AclOperations(servers) {
  enter('I11 ACL operations');
  for (const server of servers) {
    const who = server.kind;
    const cls = `I11_${suffixOf(server)}`;
    const pointer = { __type: 'Pointer', className: '_User', objectId: 'nobody' };
    for (const [label, acl] of [
      ['Delete', { __op: 'Delete' }],
      ['AddRelation', { __op: 'AddRelation', objects: [pointer] }],
      ['RemoveRelation', { __op: 'RemoveRelation', objects: [pointer] }],
    ]) {
      const made = await request(server, {
        method: 'POST', path: `/classes/${cls}`, from: 'loopback', body: { title: label, ACL: acl },
      });
      eq(`${who}: an ACL ${label} create succeeds`, made.status, 201);
      const row = await stored(cls, { _id: made.body?.objectId });
      eq(`${who}: and stores two empty permission columns`, J([row?._rperm, row?._wperm]), J([[], []]));
      const anon = await request(server, { path: `/classes/${cls}/${made.body?.objectId}`, from: 'loopback' });
      eq(`${who}: so the object is not public`, anon.status, 404);
    }
    for (const [label, acl] of [['a null entry', { '*': null }], ['a Batch operation', { __op: 'Batch', ops: [] }]]) {
      const r = await request(server, {
        method: 'POST', path: `/classes/${cls}`, from: 'loopback', body: { title: label, ACL: acl },
      });
      eq(`${who}: ${label} is a bare 500`, r.status, 500);
      eq(`${who}: ${label} writes nothing`, Boolean(await stored(cls, { title: label })), false);
    }
    const truthy = await request(server, {
      method: 'POST', path: `/classes/${cls}`, from: 'loopback', body: { title: 'truthy', ACL: { '*': { read: 1 } } },
    });
    const anon = await request(server, { path: `/classes/${cls}/${truthy.body?.objectId}`, from: 'loopback' });
    eq(`${who}: a truthy non-boolean flag grants`, anon.status, 200);
  }
}

// -------------------------------------------------------------------------------------------

function report() {
  for (const [name, expected] of Object.entries(EXPECTED)) {
    const actual = counts.get(name) ?? 0;
    if (actual !== expected) {
      failures.push(
        `[inventory] the "${name}" section ran ${actual} assertions, expected ${expected}. ` +
        'Either a block was dropped, in which case this run proves less than it appears to, or ' +
        'one was added and this number is the deliberate place to say so.',
      );
    }
  }
  for (const name of counts.keys()) {
    if (!(name in EXPECTED)) {
      failures.push(`[inventory] assertions ran in an unregistered section "${name}"`);
    }
  }
  if (failures.length === 0) {
    const breakdown = [...counts].map(([k, v]) => `${k} ${v}`).join(', ');
    console.log(`gates E and I: ${passed} assertions passed (${breakdown})`);
    process.exit(0);
  }
  console.error(`gates E and I: ${failures.length} failed, ${passed} passed`);
  for (const f of failures) { console.error(`  - ${f}`); }
  process.exit(1);
}

main().catch(e => {
  console.error('gate E: harness error');
  console.error(e);
  process.exit(1);
});
