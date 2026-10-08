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
 * Every assertion here runs against both servers. Almost all expect the same answer from each, so a
 * failure means parse-rust diverged; the few where parse-rust deliberately differs state each
 * server's answer, so they also catch parse-server changing.
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
// Several Gate I checks are about what is stored, which no response shows.
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
  'I4 limit': 24,
  'I5-6 user ACL refusals': 24,
  'I7 ACL arrays': 16,
  'I8 permission order': 4,
  'I9 objectId operation': 3,
  'I10 user update authorization': 24,
  'I11 ACL operations': 28,
  'I12 read path order': 42,
  'I13 body credentials': 42,
  'I14 routes and write order': 102,
  'I15 read parity': 62,
};

const TAG = `${process.pid}x${Date.now().toString(36)}`;
// Gate I's lockout section. A short duration, so the run does not have to wait out a real lock.
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
  // `raw` is a body string sent exactly as written. One Gate I check needs one, because an object
  // literal reorders integer-like keys before `JSON.stringify` sees them.
  const payload = raw !== undefined ? raw : body === undefined ? undefined : JSON.stringify(body);
  const all = {
    // `appId: null` sends no app id header at all, the JavaScript SDK's body-only form.
    ...(appId === null ? {} : { 'X-Parse-Application-Id': appId ?? server.appId }),
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
        resolve({ status: res.statusCode, body: json, raw, headers: res.headers });
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
    const child = spawn(process.env.PARSE_RUST_BIN || path.join(REPO, 'target/debug/parse-rust'), [], {
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
    await gateI12ReadPathOrder(defaults);
    await gateI13BodyCredentials(defaults);
    await gateI14RoutesAndWriteOrder(defaults);
    await gateI15ReadParity(defaults);
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
    //    `currentUser`, would fail while still passing that check.
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
      // parse-rust 400, a chosen difference that Gate I asserts per server.
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
// answer from both would be encoding a behavior parse-rust chose not to reproduce.
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
    for (const limit of ['-1', '-2', '1.5', '0', 'abc', '[[2]]', '2147483647', '1e12']) {
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
  // A limit beyond the driver's 32-bit batch size still answers every row.
  for (const [limit, expected] of [['-1', 1], ['-2', 2], ['1.5', 1], ['0', 0], ['abc', 3], ['[[2]]', 2], ['2147483647', 3], ['1e12', 3]]) {
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
    // Upstream accepts it and stores the row under an id nobody was told; parse-rust refuses, a
    // deliberate difference listed in CHANGELOG.md (parse-community/parse-server#10639).
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
// I12. What a read checks, in what order, and how it reads its text options
//
// Each case is one answer that depends on where a check sits in the read path, or on reading a
// text option as JavaScript's `String()` of the decoded value rather than as JSON text.
// -------------------------------------------------------------------------------------------

async function gateI12ReadPathOrder(servers) {
  enter('I12 read path order');
  const e = v => encodeURIComponent(JSON.stringify(v));
  const error = r => `${r.status} ${r.body?.code} ${r.body?.error}`;
  const fields = row => Object.keys(row ?? {}).filter(k => !['objectId', 'createdAt', 'updatedAt'].includes(k)).sort().join(',');
  const ns = r => `${r.status} ${(r.body?.results ?? []).map(x => x.n).join(',')}`;
  const badBox = e({ loc: { $within: { $box: 'x' } } });
  const cases = [
    // `limit=0` answers before the database, so before the adapter validates the explain value
    // and before the include pass walks an explain document (`RestQuery.js:864-867`).
    ['an explain with limit=0 and include answers empty', { path: '/classes/$C?explain=true&limit=0&include=x', headers: master() },
      r => `${r.status} ${J(r.body?.results)}`, '200 []'],
    ['an invalid explain value with limit=0 answers empty', { path: '/classes/$C?explain=bogus&limit=0', headers: master() },
      r => `${r.status} ${J(r.body?.results)}`, '200 []'],
    // Text options are `String()` of the decoded value (`ClassesRouter.js:194-208`).
    ['keys as an array selects each field', { path: `/classes/$C?keys=${e(['n', 'text'])}&order=n&limit=1` },
      r => `${r.status} ${fields(r.body?.results?.[0])}`, '200 n,text'],
    ['order as an array sorts', { path: `/classes/$C?order=${e(['-n'])}&keys=n` }, ns, '200 2,1,0'],
    ['keys and order as body arrays', { method: 'POST', path: '/classes/$C', body: { _method: 'GET', keys: ['n'], order: ['-n'] } },
      ns, '200 2,1,0'],
    ['keys=null is no projection', { path: '/classes/$C?keys=null&order=n&limit=1' },
      r => `${r.status} ${fields(r.body?.results?.[0])}`, '200 n,other,text'],
    // The count reruns the find's options through `DatabaseController.find`, sort included.
    ['a count validates its sort', { path: '/classes/$C?limit=0&count=1&order=%24bad' }, error,
      '400 105 Invalid field name: $bad.'],
    // An unknown top-level operator is `validateQuery`'s invalid key, raised after the gates.
    ['an unknown top-level operator is an invalid key', { path: `/classes/$C?where=${e({ $foo: 1 })}` }, error,
      '400 105 Invalid key name: $foo'],
    ['the _Session refusal comes first', { path: `/classes/_Session?where=${e({ $foo: 1 })}` }, error,
      '400 209 Permission denied'],
    ['and limit=0 never reaches it', { path: `/classes/$C?limit=0&where=${e({ $foo: 1 })}` },
      r => `${r.status} ${J(r.body?.results)}`, '200 []'],
    // The route checks parameters and decodes `where` before `rest.find` enforces class security.
    ['an unknown parameter beats class security', { path: '/classes/_Installation?bogus=1' }, error,
      '400 102 Invalid parameter for query: bogus'],
    ['malformed where JSON beats class security', { path: '/classes/_Installation?where=%7Bx' }, error,
      '400 107 where parameter is not valid JSON'],
    // A class that does not exist is still read, so its query is still built.
    ['a missing class still builds its query', { cls: 'I12m', path: `/classes/$C?where=${badBox}` }, error,
      '400 107 malformatted $within arg'],
    ['a bad query beats a negative skip', { path: `/classes/$C?skip=-1&where=${badBox}` }, error,
      '400 107 malformatted $within arg'],
    ['a negative skip alone is the database refusal', { path: '/classes/$C?skip=-1' }, error,
      '500 1 An internal server error occurred'],
    // `$all` regexes must agree on being starts-with regexes, and a lone one must be one
    // (`MongoTransform.js:143-169`). A NUL in the pattern is refused by the driver, after that check
    // and inside the read path's sanitizing `.catch`.
    ['a lone plain regex in $all is refused', { path: `/classes/$C?where=${e({ tags: { $all: [{ $regex: '^ba' }] } })}` },
      error, '400 107 All $all values must be of regex type or none: /^ba/'],
    ['a NUL in a starts-with $all regex is the database refusal', { path: `/classes/$C?where=${e({
      tags: { $all: [{ $regex: '^\\Qa\u0000b\\E' }] } })}` }, r => `${r.status} ${J(r.body)}`,
      `500 ${J({ code: 1, error: 'An internal server error occurred' })}`],
    // Operands as JavaScript reads them: a member of `null` is a `TypeError` and a bare 500, and
    // arithmetic and `isNaN` coerce (`MongoTransform.js:777-955`).
    ['$text: null is a TypeError', { cls: 'I12g', path: `/classes/$C?where=${e({ s: { $text: null } })}` },
      r => `${r.status} ${J(r.body)}`, `500 ${J({ code: 1, message: 'Internal server error.' })}`],
    ['$geoWithin: null is a TypeError', { cls: 'I12g', path: `/classes/$C?where=${e({ loc: { $geoWithin: null } })}` },
      r => `${r.status} ${J(r.body)}`, `500 ${J({ code: 1, message: 'Internal server error.' })}`],
    ['a string $maxDistanceInKilometers divides', { cls: 'I12g', path: `/classes/$C?where=${e({
      loc: { $nearSphere: { __type: 'GeoPoint', latitude: 1, longitude: 1 }, $maxDistanceInKilometers: '100' } })}` },
      r => `${r.status} ${r.body?.results?.length}`, '200 1'],
    ['a string $centerSphere distance reaches the database', { cls: 'I12g', path: `/classes/$C?where=${e({
      loc: { $geoWithin: { $centerSphere: [{ __type: 'GeoPoint', latitude: 1, longitude: 1 }, '1'] } } })}` }, error,
      '500 1 An internal server error occurred'],
  ];
  for (const server of servers) {
    const cls = `I12_${suffixOf(server)}`;
    for (let n = 0; n < 3; n++) {
      await request(server, {
        method: 'POST', path: `/classes/${cls}`, from: 'loopback', headers: master(), body: { n, text: `t${n}`, other: 'x' },
      });
    }
    await request(server, {
      method: 'POST', path: `/classes/I12g_${suffixOf(server)}`, from: 'loopback', headers: master(),
      body: { loc: { __type: 'GeoPoint', latitude: 1, longitude: 1 }, s: 'hello' },
    });
    for (const [label, { cls: prefix, path: p, ...rest }, sig, expected] of cases) {
      const target = prefix ? `${prefix}_${suffixOf(server)}` : cls;
      const r = await request(server, { ...rest, path: p.replace('$C', target), from: 'loopback' });
      eq(`${server.kind}: ${label}`, sig(r), expected);
    }
  }
}

// -------------------------------------------------------------------------------------------
// I13. Credentials and the method override travel in the body only where upstream reads them
// -------------------------------------------------------------------------------------------

/*
 * The JavaScript SDK sends its credentials in the body, with no app id header. Upstream reads them
 * there only when the header does not name the app, reads three of them and no others, and
 * overrides the method only on a `POST` (`middlewares.js:119-193`, `:425-433`). Everything it does
 * not read stays in the body, where a write refuses it as a field name.
 */
async function gateI13BodyCredentials(servers) {
  enter('I13 body credentials');
  const error = r => `${r.status} ${r.body?.code ?? ''} ${r.body?.error}`.replace('  ', ' ');
  for (const server of servers) {
    const cls = `I13_${suffixOf(server)}`;
    const { token } = await signUp(server, 'i13');
    const bodyOnly = body => ({ appId: null, raw: JSON.stringify({ _ApplicationId: server.appId, ...body }) });
    const call = opts => request(server, { from: 'loopback', ...opts });

    // With the header naming the app, the body is not consulted.
    eq(`${server.kind}: a body master key beside an app id header is not read`,
      (await call({ method: 'POST', path: '/schemas', body: { _method: 'GET', _MasterKey: MASTER_KEY } })).status, 403);
    eq(`${server.kind}: the same request with the header is master`,
      (await call({ path: '/schemas', headers: master() })).status, 200);
    eq(`${server.kind}: a body session token beside an app id header is a field`,
      error(await call({ method: 'POST', path: `/classes/${cls}`, body: { a: 1, _SessionToken: token } })),
      '400 105 Invalid field name: _SessionToken.');
    eq(`${server.kind}: so is a body maintenance key`,
      error(await call({ method: 'POST', path: `/classes/${cls}`, body: { a: 1, _MaintenanceKey: 'any' } })),
      '400 105 Invalid field name: _MaintenanceKey.');

    // Without it, the body's app id, session token, installation id and master key are read.
    eq(`${server.kind}: a maintenance key is never read from the body`,
      error(await call({ method: 'POST', path: `/classes/${cls}`, ...bodyOnly({ a: 1, _MaintenanceKey: 'any' }) })),
      '400 105 Invalid field name: _MaintenanceKey.');
    const me = await call({ method: 'POST', path: '/users/me', ...bodyOnly({ _method: 'GET', _SessionToken: token }) });
    eq(`${server.kind}: a body session token authenticates a body-only request`,
      `${me.status} ${me.body?.username === `i13_${TAG}_${server.kind}`}`, '200 true');
    eq(`${server.kind}: a non-string one is refused`,
      error(await call({ method: 'POST', path: '/users/me', ...bodyOnly({ _method: 'GET', _SessionToken: 7 }) })),
      '403 unauthorized');
    eq(`${server.kind}: a falsy one is neither read nor removed`,
      error(await call({ method: 'POST', path: `/classes/${cls}`, ...bodyOnly({ a: 1, _SessionToken: '' }) })),
      '400 105 Invalid field name: _SessionToken.');
    eq(`${server.kind}: a body app id stands in for a header naming no app`,
      (await call({ method: 'POST', path: `/classes/${cls}`, appId: 'nosuchapp', raw: JSON.stringify({ _ApplicationId: server.appId, a: 1 }) })).status,
      201);

    // The override is a `POST`'s alone, and its name is upper-cased.
    const created = await call({ method: 'POST', path: `/classes/${cls}`, body: { a: 1 } });
    const id = created.body?.objectId;
    eq(`${server.kind}: _method on a PUT is a field`,
      error(await call({ method: 'PUT', path: `/classes/${cls}/${id}`, body: { _method: 'DELETE' } })),
      '400 105 Invalid field name: _method.');
    eq(`${server.kind}: and deletes nothing`,
      (await call({ path: `/classes/${cls}/${id}` })).status, 200);
    const got = await call({ method: 'POST', path: `/classes/${cls}/${id}`, body: { _method: 'get' } });
    eq(`${server.kind}: a lower-case override is honoured`, `${got.status} ${got.body?.objectId === id}`, '200 true');

    // Context: the header is checked on every request, the body key only where the body is read,
    // and either must be a plain object (`middlewares.js:76-86`, `:173-186`).
    const malformed = '400 107 Invalid object for context.';
    const withContext = value => call({ path: `/classes/${cls}`, headers: { 'X-Parse-Cloud-Context': value } });
    eq(`${server.kind}: an array context header is malformed`, error(await withContext('[1]')), malformed);
    eq(`${server.kind}: so is one that is not JSON`, error(await withContext('nope')), malformed);
    eq(`${server.kind}: an object context header is accepted`, (await withContext('{"a":1}')).status, 200);
    eq(`${server.kind}: a body context string that parses to an array is malformed`,
      error(await call({ method: 'POST', path: `/classes/${cls}`, ...bodyOnly({ a: 1, _context: '[1]' }) })), malformed);
    eq(`${server.kind}: so is a body context number`,
      error(await call({ method: 'POST', path: `/classes/${cls}`, ...bodyOnly({ a: 1, _context: 5 }) })), malformed);
    eq(`${server.kind}: a body context object is taken and removed`,
      (await call({ method: 'POST', path: `/classes/${cls}`, ...bodyOnly({ a: 1, _context: { b: 1 } }) })).status, 201);
    eq(`${server.kind}: so is a body context array, which isObject accepts`,
      (await call({ method: 'POST', path: `/classes/${cls}`, ...bodyOnly({ a: 1, _context: [1] }) })).status, 201);
    eq(`${server.kind}: beside an app id header, a body context is a field`,
      error(await call({ method: 'POST', path: `/classes/${cls}`, body: { a: 1, _context: { b: 1 } } })),
      '400 105 Invalid field name: _context.');
  }
}

// -------------------------------------------------------------------------------------------
// I14. Routing, the login payload, and which check a write meets first
// -------------------------------------------------------------------------------------------

async function gateI14RoutesAndWriteOrder(servers) {
  enter('I14 routes and write order');
  for (const server of servers) {
    const who = server.kind;
    const sfx = suffixOf(server);
    const call = opts => request(server, { from: 'loopback', ...opts });

    // An unroutable sub-request fails the whole batch; the one before it ran, the one after did not.
    const cls = `I14Batch_${sfx}`;
    const batch = await call({
      method: 'POST', path: '/batch', headers: master(),
      body: { requests: [
        { method: 'POST', path: `/parse/classes/${cls}`, body: { n: 1 } },
        { method: 'POST', path: '/parse/nothing/here', body: {} },
        { method: 'POST', path: `/parse/classes/${cls}`, body: { n: 2 } },
      ] },
    });
    eq(`${who}: an unroutable sub-request answers 400`, batch.status, 400);
    eq(`${who}: with 107`, batch.body?.code, 107);
    // Upstream answers as soon as the throw lands, while the sub-request it already started is
    // still writing, so the row is polled for rather than read once.
    let ran = [];
    for (let i = 0; i < 20 && ran.length === 0; i++) {
      if (i) { await new Promise(r => setTimeout(r, 50)); }
      ran = (await call({ path: `/classes/${cls}`, headers: master() })).body?.results ?? [];
    }
    eq(`${who}: only the sub-request before it ran`, J(ran.map(r => r.n)), J([1]));
    const lower = await call({
      method: 'POST', path: '/batch', headers: master(),
      body: { requests: [{ method: 'post', path: `/parse/classes/${cls}`, body: {} }] },
    });
    eq(`${who}: a lower-case sub-request method does not route`, lower.body?.code, 107);
    eq(`${who}: and is named as sent`, lower.body?.error, `cannot route post /classes/${cls}`);

    // A truthy method that is not a string has no `toUpperCase`: the batch is a bare 500 before
    // anything runs, so the row survives a `["DELETE"]`.
    const target = (await call({ method: 'POST', path: `/classes/${cls}`, headers: master(), body: { n: 9 } })).body?.objectId;
    const arrayMethod = await call({
      method: 'POST', path: '/batch', headers: master(),
      body: { requests: [{ method: ['DELETE'], path: `/parse/classes/${cls}/${target}` }] },
    });
    eq(`${who}: a non-string method fails the batch`, `${arrayMethod.status} ${arrayMethod.body?.code}`, '500 1');
    eq(`${who}: and deletes nothing`, (await call({ path: `/classes/${cls}/${target}`, headers: master() })).status, 200);

    // A body over `maxUploadSize` is body-parser's 413.
    const big = await call({ method: 'POST', path: `/classes/${cls}`, headers: master(), raw: JSON.stringify({ n: 'x'.repeat(21 * 1024 * 1024) }) });
    eq(`${who}: a body over the upload limit is refused`, `${big.status} ${big.body?.error}`, '413 request entity too large');

    // A signup answers with the server-set fields upstream's does, defaults among them, and the
    // token last.
    const plain = await call({ method: 'POST', path: '/users', body: { username: `i14plain_${sfx}`, password: PASSWORD } });
    eq(`${who}: a plain signup answers objectId, createdAt, sessionToken`, J(Object.keys(plain.body ?? {})), J(['objectId', 'createdAt', 'sessionToken']));
    const field = `nick${sfx}`;
    await call({ method: 'PUT', path: '/schemas/_User', headers: master(), body: { className: '_User', fields: { [field]: { type: 'String', defaultValue: 'anon' } } } });
    const defaulted = await call({ method: 'POST', path: '/users', body: { username: `i14def_${sfx}`, password: PASSWORD } });
    eq(`${who}: a signup echoes an applied default before the token`, J(Object.keys(defaulted.body ?? {})), J(['objectId', 'createdAt', field, 'sessionToken']));
    eq(`${who}: with its value`, defaulted.body?.[field], 'anon');
    await call({ method: 'PUT', path: '/schemas/_User', headers: master(), body: { className: '_User', fields: { [field]: { __op: 'Delete' } } } });

    // A `_User` create mints a session unless its installation id is `cloud`, which a master
    // request without the header has.
    const created = async (path, headers, name) => {
      const r = await call({ method: 'POST', path, headers, body: { username: `${name}_${sfx}`, password: PASSWORD } });
      return `${r.status} ${typeof r.body?.sessionToken}`;
    };
    eq(`${who}: a master create through /classes with no installation id mints no session`,
      await created('/classes/_User', master(), 'mc1'), '201 undefined');
    eq(`${who}: one with an installation id does`,
      await created('/classes/_User', { ...master(), 'X-Parse-Installation-Id': `i-${sfx}` }, 'mc2'), '201 string');
    eq(`${who}: a master signup with no installation id mints none`,
      await created('/users', master(), 'mc3'), '201 undefined');
    eq(`${who}: a client signup always does`, await created('/users', {}, 'mc4'), '201 string');

    // Login over GET, and a body key login never reads.
    const user = await signUp(server, 'i14');
    const username = `i14_${TAG}_${server.kind}`;
    const q = `username=${encodeURIComponent(username)}&password=${encodeURIComponent(PASSWORD)}`;
    const overGet = await call({ path: `/login?${q}` });
    eq(`${who}: GET /login is served`, overGet.status, 200);
    eq(`${who}: and issues a session`, typeof overGet.body?.sessionToken, 'string');
    const stray = await call({
      method: 'POST', path: '/login',
      body: { username, password: PASSWORD, junk: { __op: 'NotAnOperation' } },
    });
    eq(`${who}: a stray operation beside the credentials does not fail a login`, stray.status, 200);

    // A caller fetching their own row gets their token back, on both routes.
    for (const p of [`/users/${user.id}`, `/classes/_User/${user.id}`]) {
      const own = await call({ path: p, headers: as(user.token) });
      eq(`${who}: ${p.split('/')[1]} returns the caller's own session token`, own.body?.sessionToken, user.token);
    }

    // `_Installation` keeps its id and its device type.
    const inst = await call({
      method: 'POST', path: '/classes/_Installation', headers: master(),
      body: { installationId: `i14-${sfx}`, deviceType: 'ios' },
    });
    eq(`${who}: an installation is created`, inst.status, 201);
    const instPath = `/classes/_Installation/${inst.body?.objectId}`;
    eq(`${who}: its installationId cannot change`,
      (await call({ method: 'PUT', path: instPath, headers: master(), body: { installationId: `x-${sfx}` } })).body?.code, 136);
    eq(`${who}: nor its deviceType, even as an operation`,
      (await call({ method: 'PUT', path: instPath, headers: master(), body: { deviceType: { __op: 'Delete' } } })).body?.code, 136);
    eq(`${who}: an update to a missing installation is named as such`,
      (await call({ method: 'PUT', path: '/classes/_Installation/i14missing', headers: master(), body: { deviceType: 'ios' } })).body?.error,
      'Object not found for update.');

    // Signup: the router's `role:` guard first, and the credentials before the restricted fields.
    eq(`${who}: a role-prefixed objectId is refused before the objectId policy`,
      (await call({ method: 'POST', path: '/users', body: { objectId: 'role:x', username: `r_${sfx}`, password: PASSWORD } })).body?.code, 119);
    eq(`${who}: a missing username is reported before emailVerified`,
      (await call({ method: 'POST', path: '/users', body: { emailVerified: true, password: PASSWORD } })).body?.code, 200);

    // A non-owner update is refused before the body is read as a write.
    const other = await signUp(server, 'i14_other');
    eq(`${who}: a non-owner's malformed update answers 206`,
      (await call({ method: 'PUT', path: `/classes/_User/${other.id}`, headers: as(user.token), body: { x: { __op: 'NotAnOperation' } } })).body?.code, 206);

    // An ACL is rendered in JavaScript key order: an array-index principal first. Checked on the
    // raw text, because `JSON.parse` would reorder it anyway.
    const aclCls = `I14Acl_${sfx}`;
    const made = await call({
      method: 'POST', path: `/classes/${aclCls}`, headers: master(),
      raw: '{"ACL":{"*":{"read":true},"123":{"read":true}}}',
    });
    const got = await call({ path: `/classes/${aclCls}/${made.body?.objectId}`, headers: master() });
    check(`${who}: an index principal precedes "*" in the rendered ACL`,
      got.raw.indexOf('"123"') >= 0 && got.raw.indexOf('"123"') < got.raw.indexOf('"*"'), got.raw);

    // An included row is a REST read's result: its timestamps are bare strings, and `keys` naming
    // only a subkey of the include still returns the pointer's object.
    const tgt = `I14Tgt_${sfx}`;
    const hold = `I14Hold_${sfx}`;
    const t = await call({ method: 'POST', path: `/classes/${tgt}`, headers: master(), body: { name: 'n', other: 'o' } });
    await call({
      method: 'POST', path: `/classes/${hold}`, headers: master(),
      body: { t: { __type: 'Pointer', className: tgt, objectId: t.body?.objectId } },
    });
    const inc = (await call({ path: `/classes/${hold}?include=t`, headers: master() })).body?.results?.[0]?.t;
    eq(`${who}: an included row's createdAt is a string`, typeof inc?.createdAt, 'string');
    eq(`${who}: and its updatedAt`, typeof inc?.updatedAt, 'string');
    const sub = (await call({ path: `/classes/${hold}?include=t&keys=t.name`, headers: master() })).body?.results?.[0]?.t;
    eq(`${who}: keys naming only an include's subkey keeps the include`, `${sub?.name} ${sub?.other}`, 'n undefined');

    // An empty session token header is no token at all.
    eq(`${who}: an empty session token header is anonymous`,
      (await call({ path: `/classes/${tgt}`, headers: { 'X-Parse-Session-Token': '' } })).status, 200);

    // `/users/me` looks its token up even for a master request.
    const meAsMaster = await call({ path: '/users/me', headers: { ...master(), ...as(user.token) } });
    eq(`${who}: /users/me with the master key and a token answers that user`,
      `${meAsMaster.status} ${meAsMaster.body?.objectId === user.id}`, '200 true');

    // Deleting someone else's user, anonymously and as another user.
    const anonDel = await call({ method: 'DELETE', path: `/users/${other.id}` });
    eq(`${who}: an anonymous user delete`, `${anonDel.status} ${anonDel.body?.code} ${anonDel.body?.error}`,
      '400 206 Insufficient auth to delete user');
    const otherDel = await call({ method: 'DELETE', path: `/users/${other.id}`, headers: as(user.token) });
    eq(`${who}: a non-owner user delete`, `${otherDel.status} ${otherDel.body?.code} ${otherDel.body?.error}`,
      '400 206 Permission denied');

    // A `userField:` rule still applies when `keys` leaves its pointer field out: the field is read
    // for the rule and not returned.
    const pp = `I14Pp_${sfx}`;
    await call({
      method: 'POST', path: `/schemas/${pp}`, headers: master(),
      body: {
        className: pp,
        fields: { title: { type: 'String' }, secret: { type: 'String' }, owner: { type: 'Pointer', targetClass: '_User' } },
        classLevelPermissions: {
          find: { '*': true }, get: { '*': true }, create: { '*': true }, update: { '*': true },
          delete: { '*': true }, addField: { '*': true }, count: { '*': true },
          protectedFields: { '*': ['secret'], 'userField:owner': [] },
        },
      },
    });
    await call({
      method: 'POST', path: `/classes/${pp}`, headers: master(),
      body: { title: 't', secret: 's', owner: { __type: 'Pointer', className: '_User', objectId: user.id } },
    });
    const mine = (await call({ path: `/classes/${pp}?keys=title,secret`, headers: as(user.token) })).body?.results?.[0];
    eq(`${who}: the userField owner sees the field with keys omitting the pointer`, mine?.secret, 's');
    eq(`${who}: and the pointer field read for the rule is not returned`, mine?.owner, undefined);
    const theirs = (await call({ path: `/classes/${pp}?keys=title,secret`, headers: as(other.token) })).body?.results?.[0];
    eq(`${who}: another user still does not`, theirs?.secret, undefined);

    // Routing on the effective method (`allowMethodOverride` runs before every router), the body a
    // write starts from (body-parser's `{}`), and the create's `Location`.
    const mc = `I14M_${sfx}`;
    eq(`${who}: a POST overridden to GET reaches /serverInfo`,
      (await call({ method: 'POST', path: '/serverInfo', headers: master(), body: { _method: 'GET' } })).status, 200);
    eq(`${who}: a method no route serves is 404`,
      (await call({ method: 'PATCH', path: `/classes/${mc}`, body: {} })).status, 404);
    eq(`${who}: logout overridden to GET is 404`,
      (await call({ method: 'POST', path: '/logout', body: { _method: 'GET' } })).status, 404);
    eq(`${who}: an override naming no method is 404`,
      (await call({ method: 'POST', path: `/classes/${mc}`, body: { _method: 'BO GUS', a: 1 } })).status, 404);
    const bare = await call({ method: 'POST', path: `/classes/${mc}` });
    eq(`${who}: a create with no body is an empty create`, bare.status, 201);
    eq(`${who}: and names its object in Location`,
      (bare.headers?.location ?? '').endsWith(`/parse/classes/${mc}/${bare.body?.objectId}`), true);
    const txn = await call({ method: 'POST', path: '/batch', body: { transaction: true, requests: 5 } });
    eq(`${who}: a malformed transactional batch is a malformed batch`, `${txn.status} ${txn.body?.code}`, '400 107');
    const dots = await call({
      method: 'POST', path: '/batch',
      body: { requests: [{ method: 'GET', path: `/parse/./classes/../classes/${mc}` }] },
    });
    eq(`${who}: batch paths are normalized as a posix join`, Array.isArray(dots.body?.[0]?.success?.results), true);

    // Field options: `required` and `defaultValue` (`RestWrite.js:408-436`).
    const rq = `I14Req_${sfx}`;
    await call({
      method: 'POST', path: `/schemas/${rq}`, headers: master(),
      body: { className: rq, fields: { title: { type: 'String', required: true }, score: { type: 'Number', defaultValue: 5 } } },
    });
    eq(`${who}: a missing required field is 142`,
      J((await call({ method: 'POST', path: `/classes/${rq}`, body: {} })).body), J({ code: 142, error: 'title is required' }));
    const withDefault = await call({ method: 'POST', path: `/classes/${rq}`, body: { title: 't' } });
    eq(`${who}: a default is applied and echoed`, withDefault.body?.score, 5);
    eq(`${who}: an update clearing a required field is 142`,
      (await call({ method: 'PUT', path: `/classes/${rq}/${withDefault.body?.objectId}`, body: { title: null } })).body?.code, 142);
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

// -------------------------------------------------------------------------------------------
// I15. Where a read's `where`, `keys`, `include` and `order` fail, and how pointers come back
// -------------------------------------------------------------------------------------------

/*
 * Upstream reads `where` in stages: the route decodes it, `RestQuery` checks the shape of the
 * logical operators, and operands are converted only when the database query is built, after
 * the CLP gate (`ClassesRouter.js:32-37`, `RestQuery.js:942-967`, `DatabaseController.js:1524`).
 * Dotted `keys` force their parent's include (`RestQuery.js:146-183`), and pointers come back as
 * the transform writes them (`MongoTransform.js:1211-1233`).
 */
async function gateI15ReadParity(servers) {
  enter('I15 read parity');
  const e = v => encodeURIComponent(JSON.stringify(v));
  const error = r => `${r.status} ${r.body?.code} ${r.body?.error ?? r.body?.message}`;
  const count = r => `${r.status} ${r.body?.results?.length}`;
  const fields = row => Object.keys(row ?? {}).filter(k => !['objectId', 'createdAt', 'updatedAt'].includes(k)).sort().join(',');
  for (const server of servers) {
    const who = server.kind;
    const sfx = suffixOf(server);
    const call = opts => request(server, { from: 'loopback', ...opts });
    const C = `I15_${sfx}`;
    for (let n = 0; n < 3; n++) {
      await call({ method: 'POST', path: `/classes/${C}`, headers: master(), body: { n } });
    }
    const D = `I15Closed_${sfx}`;
    await call({ method: 'POST', path: `/schemas/${D}`, headers: master(), body: {
      classLevelPermissions: { find: {}, get: {}, count: {}, create: {}, update: {}, delete: {}, addField: {} },
    } });

    // Operand errors come after the CLP gate and never on a `limit=0` read.
    eq(`${who}: a bad operand on a class the CLP closes is the CLP refusal`,
      error(await call({ path: `/classes/${D}?where=${e({ n: { $in: 5 } })}` })), '400 119 Permission denied');
    eq(`${who}: a bad operand with limit=0 answers empty`,
      `${(await call({ path: `/classes/${C}?limit=0&where=${e({ n: { $in: 5 } })}` })).body?.results?.length}`, '0');
    eq(`${who}: $in with a non-array is 107`, error(await call({ path: `/classes/${C}?where=${e({ n: { $in: 5 } })}` })),
      '400 107 bad $in value');
    eq(`${who}: an unknown operator is 107`, error(await call({ path: `/classes/${C}?where=${e({ n: { $foo: 1 } })}` })),
      '400 107 bad constraint: $foo');
    eq(`${who}: $exists reads truthiness`, count(await call({ path: `/classes/${C}?where=${e({ n: { $exists: 1 } })}` })), '200 3');

    // The shapes a `where` that is not an object takes.
    eq(`${who}: a numeric where is a 500 for a client`, error(await call({ path: `/classes/${C}?where=5` })),
      '500 1 Internal server error.');
    eq(`${who}: and every row for master`, count(await call({ path: `/classes/${C}?where=5`, headers: master() })), '200 3');
    eq(`${who}: a null where is a 500`, error(await call({ path: `/classes/${C}?where=null`, headers: master() })),
      '500 1 Internal server error.');
    eq(`${who}: an array where names its indices`, error(await call({ path: `/classes/${C}?where=%5B1%5D` })),
      '400 105 Invalid key name: 0');
    eq(`${who}: a where that is a JSON string is parsed again`, error(await call({ path: `/classes/${C}?where=%22s%22` })),
      '400 107 where parameter is not valid JSON');
    // Malformed queries parse-rust refuses as such where upstream answers a 500, a misleading
    // `Permission denied`, or a widened result: deliberate differences, each stated per server.
    const rust = server.kind === 'parse-rust';
    const pick = (mine, theirs) => (rust ? mine : theirs);
    eq(`${who}: $or that is not an array, from a client`,
      error(await call({ path: `/classes/${C}?where=${e({ $or: 5 })}` })),
      pick('400 102 Bad $or format - use an array value.', '400 102 Permission denied'));
    eq(`${who}: and from master`,
      error(await call({ path: `/classes/${C}?where=${e({ $or: 5 })}`, headers: master() })),
      pick('400 102 Bad $or format - use an array value.', '500 1 Internal server error.'));
    eq(`${who}: an empty $or`,
      error(await call({ path: `/classes/${C}?where=${e({ $or: [] })}` })),
      pick('400 102 Bad $or format - use an array of at least 1 value.', '500 1 An internal server error occurred'));
    eq(`${who}: a non-object $or element`,
      (await call({ path: `/classes/${C}?where=${e({ $or: [1] })}` })).status,
      pick(400, 200));
    eq(`${who}: a lone $options`,
      error(await call({ path: `/classes/${C}?where=${e({ n: { $options: 'i' } })}` })),
      pick('400 102 $options is only valid with $regex', '500 1 An internal server error occurred'));
    // Parity: master's malformed $nor, $exists given an object on a plain field, and which of two
    // malformed operators is reported.
    eq(`${who}: master's $nor that is not an array`,
      error(await call({ path: `/classes/${C}?where=${e({ $nor: 5 })}`, headers: master() })),
      '400 102 Bad $nor format - use an array of at least 1 value.');
    eq(`${who}: $exists given an object on a plain field`,
      error(await call({ path: `/classes/${C}?where=${e({ n: { $exists: {} } })}` })),
      '400 107 bad atom: {}');
    eq(`${who}: a non-string $regex is refused before its options`,
      error(await call({ path: `/classes/${C}?where=${e({ n: { $regex: 3, $options: 'z' } })}` })),
      '400 102 $regex value must be a string');
    eq(`${who}: a protected field beside a malformed $or is refused for the field first`,
      error(await call({ path: `/classes/_User?where=${e({ email: 'x', $or: 5 })}` })),
      '400 119 Permission denied');
    eq(`${who}: an invalid key name is reported before its malformed operand`,
      error(await call({ path: `/classes/${C}?where=${e({ 'bad-key': { $in: 5 } })}` })),
      '400 105 Invalid key name: bad-key');
    eq(`${who}: of two malformed operators, the later name is reported`,
      error(await call({ path: `/classes/${C}?where=${e({ n: { $in: 5, $nin: 5 } })}` })),
      '400 107 bad $nin value');

    // Order: the internal timestamp names alias the public ones, and an empty entry is a field.
    eq(`${who}: order=_created_at sorts`, count(await call({ path: `/classes/${C}?order=_created_at` })), '200 3');
    eq(`${who}: an empty order entry is refused`, error(await call({ path: `/classes/${C}?order=n,` })),
      '400 105 Invalid field name: .');

    // keys and include are split and never trimmed.
    eq(`${who}: a key with a leading space names no field`,
      fields((await call({ path: `/classes/${C}?keys=%20n&limit=1` })).body?.results?.[0]), '');

    // Pointers: a dotted key includes its parent; a null pointer has no key.
    const A = `I15A_${sfx}`;
    const author = (await call({ method: 'POST', path: `/classes/${A}`, headers: master(), body: { name: 'x', secret: 's' } })).body?.objectId;
    const H = `I15H_${sfx}`;
    const ptr = { __type: 'Pointer', className: A, objectId: author };
    await call({ method: 'POST', path: `/classes/${H}`, headers: master(), body: { k: 1, author: ptr } });
    // Created null, a pointer reads back as `null`; updated to null, it reads back with no key.
    await call({ method: 'POST', path: `/classes/${H}`, headers: master(), body: { k: 2, author: null } });
    const later = (await call({ method: 'POST', path: `/classes/${H}`, headers: master(), body: { k: 3, author: ptr } })).body?.objectId;
    await call({ method: 'PUT', path: `/classes/${H}/${later}`, headers: master(), body: { author: null } });
    const dotted = (await call({ path: `/classes/${H}?keys=author.name&where=${e({ k: 1 })}` })).body?.results?.[0]?.author;
    eq(`${who}: keys=author.name includes author with only name`,
      `${dotted?.__type} ${dotted?.name} ${'secret' in (dotted ?? {})}`, 'Object x false');
    const spaced = (await call({ path: `/classes/${H}?include=%20author&where=${e({ k: 1 })}` })).body?.results?.[0]?.author;
    eq(`${who}: an include with a leading space includes nothing`, spaced?.__type, 'Pointer');
    const created = (await call({ path: `/classes/${H}?where=${e({ k: 2 })}` })).body?.results?.[0];
    eq(`${who}: a pointer created null reads back null`, J(created?.author), 'null');
    const updated = (await call({ path: `/classes/${H}?where=${e({ k: 3 })}` })).body?.results?.[0];
    eq(`${who}: a pointer updated to null reads back with no key`, 'author' in (updated ?? {}), false);

    // A `userField:` rule over an array of pointers grants the user it names.
    const user = await signUp(server, 'i15');
    const U = `I15U_${sfx}`;
    const userPtr = { __type: 'Pointer', className: '_User', objectId: user.id };
    await call({ method: 'POST', path: `/classes/${U}`, headers: master(), body: { owners: [userPtr], secret: 's' } });
    const clp = await call({ method: 'PUT', path: `/schemas/${U}`, headers: master(), body: {
      classLevelPermissions: { find: { '*': true }, get: { '*': true }, protectedFields: { '*': ['secret'], 'userField:owners': [] } },
    } });
    eq(`${who}: the userField CLP is accepted`, clp.status, 200);
    const own = (await call({ path: `/classes/${U}`, headers: as(user.token) })).body?.results?.[0];
    eq(`${who}: an owner listed in an array sees the protected field`, own?.secret, 's');
  }
}
