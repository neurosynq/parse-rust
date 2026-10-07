/*
 * Gate F of 0.3.0: upstream's own spec files, executed against parse-rust, block by block.
 *
 *   node tools/conformance/run.mjs [--target rust|upstream|dead|all] [--classify] [--files A,B]
 *
 * `all`, the default, is the gate: parse-rust, then the dead-server control, then the pinned
 * parse-server. `--classify` runs against the pinned parse-server only and rewrites
 * `inventory.json`; that is a deliberate act with a diff to review, never a side effect of a run.
 *
 * **How each run proves its subject**, per the contract:
 *   - Every request carries `X-Parse-Conformance-Block`. parse-rust counts them server-side
 *     (`/_control/stats`), and a `server-dependent` block that passed with no body-phase request
 *     of its own on parse-rust fails the gate; a `client-only` block that sent one fails too.
 *   - With no server at all, the set of blocks that still pass must equal the committed
 *     `client-only` set exactly.
 *   - The identical patched suite must pass against parse-server built at the pin, so a rewrite
 *     cannot have changed what is asked.
 *
 * The two rewrites applied to upstream's spec text are the only two permitted (contract section
 * 4): the hardcoded `http://localhost:8378/1` becomes `global.CONFORMANCE_SERVER_URL`, and
 * `require('../lib/{rest,Config,Auth}')` resolves to a throwing stub. The second needs no text
 * change at all: the vendored tree places the stubs at the path those requires resolve to.
 */

import crypto from 'node:crypto';
import fs from 'node:fs';
import http from 'node:http';
import net from 'node:net';
import path from 'node:path';
import { spawn } from 'node:child_process';
import { createRequire } from 'node:module';
import { fileURLToPath } from 'node:url';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const REPO = path.resolve(HERE, '..', '..');
const PS_ROOT = path.resolve(REPO, process.env.PARSE_SERVER_ROOT || '../parse-server-pinned');
const require = createRequire(`${PS_ROOT}/`);
const { MongoClient } = require(`${PS_ROOT}/node_modules/mongodb`);
const MONGO = process.env.CONFORMANCE_MONGO || process.env.PARSE_RUST_TEST_MONGO || 'mongodb://127.0.0.1:27017';
const INVENTORY = path.join(HERE, 'inventory.json');
const EXCLUSIONS = path.join(HERE, 'exclusions.json');
const RUST_BIN = path.join(REPO, 'target/harness/debug/parse-rust');

const args = process.argv.slice(2);
const opt = name => { const i = args.indexOf(name); return i >= 0 ? args[i + 1] : undefined; };
const target = opt('--target') || 'all';
const classify = args.includes('--classify');
const inventory = fs.existsSync(INVENTORY) ? JSON.parse(fs.readFileSync(INVENTORY, 'utf8')) : null;
// Gate H condition 4's acceptance files. Not conformance rows, so not in the inventory.
const CONTROL_FILES = ['index.spec.js', 'PasswordPolicy.spec.js'];
const defaultFiles = args.includes('--control-plane')
  ? CONTROL_FILES.join(',')
  : (inventory ? Object.keys(inventory.files).join(',') : '');
const files = (opt('--files') || defaultFiles).split(',').filter(Boolean);
if (files.length === 0) {
  console.error('no spec files: pass --files, or commit an inventory');
  process.exit(2);
}

const TAG = `${process.pid}x${Date.now().toString(36)}`;

// The floors the 0.3.0 contract commits, used when a file is first classified. A floor already in
// the inventory is never replaced by a run.
const FLOORS = {
  'ParseObject.spec.js': 82,
  'ParseGeoPoint.spec.js': 34,
  'ParseRelation.spec.js': 19,
  'PointerPermissions.spec.js': 90,
  'ParseQuery.spec.js': 223,
  // Not in the contract's target set; added once `$text` landed, at its executable count.
  'ParseQuery.FullTextSearch.spec.js': 11,
};
// Gate G condition 1. A floor counts executed blocks, so it cannot say a file is green; this does.
const MUST_BE_GREEN = ['ParseGeoPoint.spec.js'];
const WORK = path.join(REPO, 'target/conformance', TAG);

// -------------------------------------------------------------------------------------------
// Vendoring
// -------------------------------------------------------------------------------------------

/** The declared rewrite, and only it. Every quote style the suite uses. */
function rewriteUrls(text) {
  return text
    .replace(/'http:\/\/localhost:8378\/1/g, "global.CONFORMANCE_SERVER_URL + '")
    .replace(/"http:\/\/localhost:8378\/1/g, 'global.CONFORMANCE_SERVER_URL + "')
    .replace(/`http:\/\/localhost:8378\/1/g, '`${global.CONFORMANCE_SERVER_URL}');
}

const sha = text => crypto.createHash('sha256').update(text).digest('hex').slice(0, 16);

/**
 * Upstream modules with no server in them, which a spec may use as they are: helpers and the
 * option definitions. Anything not here and not hand-written in `tools/conformance/lib` gets a
 * generated in-process stub.
 */
const PURE_LIBS = new Set(['Utils', 'Options/Definitions', 'Options/Definitions.js', 'Adapters/Auth/utils']);

/**
 * For every `require('../lib/<x>')` a vendored spec makes that `tools/conformance/lib` does not
 * provide, write one: a re-export for a pure module, an in-process stub for anything else. The stub
 * loads, so the file's other blocks run, and throws on any use, naming the module.
 */
function stubMissingLibs(source) {
  for (const m of source.matchAll(/require\(['"]\.\.\/lib\/([^'"]+)['"]\)/g)) {
    const name = m[1].replace(/\.js$/, '');
    const target = path.join(WORK, 'lib', `${name}.js`);
    if (fs.existsSync(target)) { continue; }
    fs.mkdirSync(path.dirname(target), { recursive: true });
    const inprocess = path.relative(path.dirname(target), path.join(WORK, 'lib', 'inprocess.js'));
    fs.writeFileSync(target, PURE_LIBS.has(name) || PURE_LIBS.has(m[1])
      ? `'use strict';\nmodule.exports = require(require('path').join(process.env.PS_ROOT, 'lib/${name}'));\n`
      : `'use strict';\n// Generated by run.mjs: \`../lib/${name}\` drives parse-server in process.\n` +
        `const inProcess = require('./${inprocess.split(path.sep).join('/')}');\n` +
        `module.exports = new Proxy({}, { get(_, p) { if (p === '__esModule') { return true; } ` +
        `if (typeof p === 'symbol' || p === 'then') { return undefined; } return inProcess('${name}.' + String(p)); } });\n`);
  }
}

function vendor() {
  fs.mkdirSync(path.join(WORK, 'spec/helpers'), { recursive: true });
  fs.cpSync(path.join(HERE, 'lib'), path.join(WORK, 'lib'), { recursive: true });
  // A spec's bare `require('parse/node')` resolves through here to the pinned checkout's SDK. Node
  // follows the link to its real path, so the spec and the helper share one SDK instance.
  fs.symlinkSync(path.join(PS_ROOT, 'node_modules'), path.join(WORK, 'node_modules'), 'dir');
  fs.copyFileSync(path.join(HERE, 'helper.js'), path.join(WORK, 'spec/helpers/conformance.js'));
  // A spec's own fixtures (`./support/...`) and `../package.json`, as upstream has them.
  fs.cpSync(path.join(PS_ROOT, 'spec/support'), path.join(WORK, 'spec/support'), { recursive: true });
  fs.copyFileSync(path.join(PS_ROOT, 'package.json'), path.join(WORK, 'package.json'));
  const hashes = {};
  for (const file of files) {
    const original = fs.readFileSync(path.join(PS_ROOT, 'spec', file), 'utf8');
    const patched = rewriteUrls(original);
    fs.writeFileSync(path.join(WORK, 'spec', file), patched);
    hashes[file] = { upstream: sha(original), patched: sha(patched) };
    stubMissingLibs(original);
  }
  fs.writeFileSync(path.join(WORK, 'jasmine.json'), JSON.stringify({
    spec_dir: 'spec',
    spec_files: files,
    helpers: ['helpers/conformance.js'],
    random: true,
  }));
  return hashes;
}

// -------------------------------------------------------------------------------------------
// Targets
// -------------------------------------------------------------------------------------------

/** A port nothing listens on: bound, read, released. */
async function deadPort() {
  return new Promise(resolve => {
    const s = net.createServer().listen(0, '127.0.0.1', () => {
      const { port } = s.address();
      s.close(() => resolve(port));
    });
  });
}

/** Upstream's fast `deleteAllClasses`: every collection emptied, indexes kept. */
function resetServer(dbUri) {
  return new Promise(resolve => {
    let client;
    const server = http.createServer(async (req, res) => {
      try {
        client ??= await MongoClient.connect(dbUri);
        const db = client.db();
        for (const c of await db.listCollections({}, { nameOnly: true }).toArray()) {
          if (!c.name.startsWith('system.')) { await db.collection(c.name).deleteMany({}); }
        }
        res.writeHead(200).end('{}');
      } catch (e) {
        res.writeHead(500).end(String(e));
      }
    }).listen(0, '127.0.0.1', () => resolve({
      url: `http://127.0.0.1:${server.address().port}/reset`,
      close: async () => { server.close(); if (client) { await client.close(); } },
    }));
  });
}

function waitForLine(child, pattern, what) {
  return new Promise((resolve, reject) => {
    let log = '';
    const timer = setTimeout(() => { child.kill(); reject(new Error(`${what} never started:\n${log}`)); }, 30000);
    const onData = chunk => {
      log += chunk;
      const m = pattern.exec(log);
      if (m) { clearTimeout(timer); resolve(m); }
    };
    child.stdout.on('data', onData);
    child.stderr.on('data', chunk => { log += chunk; });
    child.on('exit', code => { clearTimeout(timer); reject(new Error(`${what} exited with ${code}:\n${log}`)); });
  });
}

// -------------------------------------------------------------------------------------------
// reconfigureServer: Gate H
// -------------------------------------------------------------------------------------------

/**
 * Upstream option names parse-rust honors, and the environment variable each becomes. **A key not
 * here is refused by name** (Gate H condition 1): silently ignoring it would turn a red block
 * green without parse-rust doing anything.
 */
const MAPPED = {
  defaultLimit: v => ({ PARSE_SERVER_DEFAULT_LIMIT: String(v) }),
  maxLimit: v => ({ PARSE_SERVER_MAX_LIMIT: String(v) }),
  'databaseOptions.allowPublicExplain': v => ({ PARSE_SERVER_DATABASE_ALLOW_PUBLIC_EXPLAIN: String(v) }),
  allowClientClassCreation: v => ({ PARSE_SERVER_ALLOW_CLIENT_CLASS_CREATION: String(v) }),
  allowCustomObjectId: v => ({ PARSE_SERVER_ALLOW_CUSTOM_OBJECT_ID: String(v) }),
  enableSanitizedErrorResponse: v => ({ PARSE_SERVER_ENABLE_SANITIZED_ERROR_RESPONSE: String(v) }),
  accountLockout: v => ({ PARSE_SERVER_ACCOUNT_LOCKOUT: JSON.stringify(v) }),
  protectedFieldsOwnerExempt: v => ({ PARSE_SERVER_PROTECTED_FIELDS_OWNER_EXEMPT: String(v) }),
  protectedFieldsSaveResponseExempt: v => ({ PARSE_SERVER_PROTECTED_FIELDS_SAVE_RESPONSE_EXEMPT: String(v) }),
  'requestComplexity.batchRequestLimit': v => ({ PARSE_SERVER_REQUEST_COMPLEXITY_BATCH_REQUEST_LIMIT: String(v) }),
  // Comma-separated, upstream's own environment spelling. The empty list is not expressible this
  // way, here or upstream, and is refused rather than mapped to the default.
  masterKeyIps: v => {
    if (!Array.isArray(v) || v.length === 0) {
      throw new Error("reconfigure: parse-rust cannot map option 'masterKeyIps' as given");
    }
    return { PARSE_SERVER_MASTER_KEY_IPS: v.join(',') };
  },
};

/**
 * Keys accepted with no effect, each for a stated reason. Not a way to silence a key: an entry
 * here is a claim that the option cannot change anything an out-of-process client observes.
 */
const INERT = {
  // Routes Cloud Code's own requests in process. parse-rust has no Cloud Code, and a block that
  // relies on it drives `ParseServerRESTController`, which the harness stubs to throw.
  directAccess: 'only changes in-process server-to-server calls',
  // The harness runs every target against its own per-run database, so a spec's fixed
  // `mongodb://localhost:27017/parse` is mapped onto that one rather than onto a shared database
  // other runs also use. Same reasoning as `collectionPrefix`, contract section 4.
  databaseURI: 'mapped to the run\'s own database',
  databaseAdapter: 'only `undefined` is accepted, which selects `databaseURI`',
};

/** A value `helper.js` could not send as JSON: a function, a RegExp, an adapter instance. */
const isUnserializable = v => Boolean(v && typeof v === 'object' && '__unserializable' in v);

/** The first key carrying a value that cannot reach an out-of-process server, if any. */
function firstUnserializable(options) {
  for (const [key, value] of Object.entries(flattenOptions(options))) {
    if (isUnserializable(value)) { return { key, kind: value.__unserializable }; }
  }
  return null;
}

/** Flatten nested option objects to dotted keys, as far as a mapped key goes. */
function flattenOptions(options, prefix = '') {
  const out = {};
  for (const [k, v] of Object.entries(options)) {
    const key = prefix + k;
    if (v && typeof v === 'object' && !Array.isArray(v) && !isUnserializable(v) && !MAPPED[key] && !INERT[key]) {
      Object.assign(out, flattenOptions(v, `${key}.`));
    } else {
      out[key] = v;
    }
  }
  return out;
}

/** The env a reconfigure asks for, or an error naming the first key that cannot be mapped. */
function mapOptions(options) {
  const lost = firstUnserializable(options);
  if (lost) {
    throw new Error(`reconfigure: parse-rust cannot map option '${lost.key}' (a ${lost.kind} cannot cross to an out-of-process server)`);
  }
  const env = {};
  for (const [key, value] of Object.entries(flattenOptions(options))) {
    if (MAPPED[key]) { Object.assign(env, MAPPED[key](value)); continue; }
    if (key === 'databaseAdapter' && value === undefined) { continue; }
    if (INERT[key] && key !== 'databaseAdapter') { continue; }
    throw new Error(`reconfigure: parse-rust cannot map option '${key}'`);
  }
  return env;
}

/**
 * Whether the running value is the one asked for. Objects compare by the keys asked for, in any
 * order, so a resolved block carrying a default the request left out (`accountLockout`'s
 * `unlockOnPasswordReset`) is not a mismatch.
 */
function sameOption(running, asked) {
  if (asked && typeof asked === 'object' && !Array.isArray(asked)) {
    return Boolean(running && typeof running === 'object')
      && Object.entries(asked).every(([k, v]) => sameOption(running[k], v));
  }
  return JSON.stringify(running) === JSON.stringify(asked);
}

/** Read a dotted key out of the resolved option set. */
function dig(object, key) {
  return key.split('.').reduce((o, k) => (o == null ? undefined : o[k]), object);
}

async function startRust(dbUri) {
  let current = await spawnRust(dbUri, {});
  let lastEnv = {};
  // Per-block counts live in the process, so a respawn would erase the evidence. A process is
  // folded into `retired` once, as it is replaced, and the live one is read alongside.
  const retired = {};
  const fold = (into, blocks) => {
    for (const [k, c] of Object.entries(blocks)) {
      into[k] ??= { body: 0, lifecycle: 0 };
      into[k].body += c.body;
      into[k].lifecycle += c.lifecycle;
    }
  };
  const reset = await resetServer(dbUri);
  return {
    kind: 'parse-rust',
    get url() { return current.url; },
    reset: reset.url,
    async stats() {
      const out = structuredClone(retired);
      fold(out, await current.stats());
      return out;
    },
    panics: () => current.panics(),
    async reconfigure(options) {
      const env = mapOptions(options); // throws naming an unmapped key; the running server is untouched
      fold(retired, await current.stats());
      current.kill();
      try {
        current = await spawnRust(dbUri, env);
      } catch (e) {
        // A configuration parse-rust refuses at boot is a rejected reconfigure, as it is upstream,
        // and the previous configuration comes back so the next block has a server. The refusal
        // names the upstream option, found by the environment variable the boot error names.
        current = await spawnRust(dbUri, lastEnv);
        const reason = String(e.message).split('\n').filter(Boolean).slice(-1)[0];
        const flat = flattenOptions(options);
        const key = Object.keys(flat).find(k => MAPPED[k] && Object.keys(MAPPED[k](flat[k])).some(v => reason.includes(v)));
        throw new Error(`reconfigure: parse-rust refused option '${key ?? 'unknown'}' at boot: ${reason}`);
      }
      // Condition 2: every mapped key reads back as asked, so nothing was dropped on the way. A
      // mismatch restores the previous configuration before refusing, so later blocks do not run
      // on a configuration nobody asked for.
      const resolved = await (await fetch(`${current.base}/_control/config`)).json();
      for (const [key, value] of Object.entries(flattenOptions(options))) {
        if (!MAPPED[key]) { continue; }
        if (!sameOption(dig(resolved, key), value)) {
          fold(retired, await current.stats());
          current.kill();
          current = await spawnRust(dbUri, lastEnv);
          throw new Error(`reconfigure: '${key}' did not take effect: asked ${JSON.stringify(value)}, running ${JSON.stringify(dig(resolved, key))}`);
        }
      }
      lastEnv = env;
      return { url: current.url, reset: reset.url, options: resolved };
    },
    stop: async () => { current.kill(); await reset.close(); },
  };
}

async function spawnRust(dbUri, extraEnv) {
  if (!fs.existsSync(RUST_BIN)) {
    throw new Error(`${RUST_BIN} is missing. Build it with:\n  CARGO_TARGET_DIR=target/harness cargo build -p parse-rust-cli --features test-harness`);
  }
  const child = spawn(RUST_BIN, [], {
    env: {
      ...process.env,
      PARSE_RUST_TESTING: '1',
      PARSE_SERVER_APPLICATION_ID: 'test',
      PARSE_SERVER_MASTER_KEY: 'test',
      PARSE_SERVER_JAVASCRIPT_KEY: 'test',
      PARSE_SERVER_CLIENT_KEY: 'client',
      PARSE_SERVER_REST_API_KEY: 'rest',
      PARSE_SERVER_DOT_NET_KEY: 'windows',
      PARSE_SERVER_ALLOW_CLIENT_CLASS_CREATION: 'true',
      PARSE_SERVER_MOUNT_PATH: '/1',
      PARSE_SERVER_HOST: '127.0.0.1',
      PARSE_SERVER_DATABASE_URI: dbUri,
      PORT: '0',
      ...extraEnv,
    },
  });
  let stderr = '';
  child.stderr.on('data', c => { stderr += c; });
  const m = await waitForLine(child, /parse-rust listening on http:\/\/(\S+)/, 'parse-rust');
  child.removeAllListeners('exit');
  const base = `http://${m[1]}`;
  return {
    base,
    url: `${base}/1`,
    stats: async () => (await (await fetch(`${base}/_control/stats`)).json()).blocks,
    panics: () => (stderr.match(/panicked at/g) || []).length,
    kill: () => child.kill(),
  };
}

async function spawnOracle(dbUri, options) {
  const child = spawn(process.execPath, [path.join(HERE, 'oracle.mjs')], {
    env: { ...process.env, PS_ROOT, CONFORMANCE_DB_URI: dbUri, CONFORMANCE_OPTIONS: JSON.stringify(options) },
  });
  const m = await waitForLine(child, /^ORACLE (\{.*\})$/m, 'parse-server');
  child.removeAllListeners('exit');
  return { ...JSON.parse(m[1]), kill: () => child.kill() };
}

async function startUpstream(dbUri) {
  let current = await spawnOracle(dbUri, {});
  let lastOptions = {};
  return {
    kind: 'parse-server',
    get url() { return current.url; },
    get reset() { return current.reset; },
    async reconfigure(options) {
      // Upstream takes its own options as they are, but on the run's database, as above.
      const { databaseURI: _uri, databaseAdapter: _adapter, ...rest } = options;
      // The same rule as parse-rust's side: a value that could not be sent is refused by name
      // rather than handed to parse-server as an empty object.
      const lost = firstUnserializable(rest);
      if (lost) {
        throw new Error(`reconfigure: cannot pass option '${lost.key}' (a ${lost.kind}) to an out-of-process server`);
      }
      current.kill();
      try {
        current = await spawnOracle(dbUri, rest);
      } catch (e) {
        // A configuration parse-server refuses at boot is a rejected reconfigure upstream too, and
        // the previous configuration comes back, as on parse-rust's side.
        current = await spawnOracle(dbUri, lastOptions);
        throw new Error(String(e.message).split('\n').find(l => l.trim()) || 'reconfigure failed');
      }
      lastOptions = rest;
      return { url: current.url, reset: current.reset, options: rest };
    },
    stop: async () => { current.kill(); },
  };
}

async function startDead(dbUri) {
  const reset = await resetServer(dbUri);
  const url = `http://127.0.0.1:${await deadPort()}/1`;
  return {
    kind: 'dead', url, reset: reset.url,
    async reconfigure() { return { url, reset: reset.url, options: {} }; },
    stop: reset.close,
  };
}

/**
 * The supervisor `reconfigureServer` talks to, for the life of one suite run. Every refusal is
 * recorded against the block that asked, which is what Gate H condition 4 judges.
 */
function supervisor(server) {
  const refusals = [];
  return new Promise(resolve => {
    const http_ = http.createServer((req, res) => {
      let raw = '';
      req.on('data', c => { raw += c; });
      req.on('end', async () => {
        try {
          const { options = {} } = JSON.parse(raw || '{}');
          const body = await server.reconfigure(options);
          res.writeHead(200, { 'Content-Type': 'application/json' }).end(JSON.stringify(body));
        } catch (e) {
          const block = String(req.headers['x-parse-conformance-block'] || '').split(';')[0];
          refusals.push({ block, error: e.message });
          // A refusal may have restarted the server on a new port to restore the previous
          // configuration, so the addresses go back with it: a client left on the old ones would
          // fail every later block against a process that no longer exists.
          res.writeHead(400, { 'Content-Type': 'application/json' }).end(JSON.stringify({
            error: e.message, url: server.url, reset: server.reset,
          }));
        }
      });
    }).listen(0, '127.0.0.1', () => resolve({
      url: `http://127.0.0.1:${http_.address().port}/reconfigure`,
      refusals,
      close: () => new Promise(done => http_.close(done)),
    }));
  });
}

// -------------------------------------------------------------------------------------------
// Running
// -------------------------------------------------------------------------------------------

async function runSuite(server, label) {
  const resultsPath = path.join(WORK, `results-${label}.json`);
  const control = await supervisor(server);
  const child = spawn(process.execPath, [
    path.join(PS_ROOT, 'node_modules/jasmine/bin/jasmine.js'),
    `--config=${path.join(WORK, 'jasmine.json')}`,
  ], {
    cwd: WORK,
    env: {
      ...process.env,
      PS_ROOT,
      CONFORMANCE_SERVER_URL: server.url,
      CONFORMANCE_RESET_URL: server.reset,
      CONFORMANCE_RESULTS: resultsPath,
      CONFORMANCE_EXCLUSIONS: EXCLUSIONS,
      CONFORMANCE_SUPERVISOR_URL: control.url,
      // With no server, a block waiting on a `done` that never comes runs to the timeout. Every
      // such block fails either way; a short timeout only stops the control taking twenty minutes.
      ...(server.kind === 'dead' ? { PARSE_SERVER_TEST_TIMEOUT: '1500' } : {}),
    },
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  let out = '';
  child.stdout.on('data', c => { out += c; });
  child.stderr.on('data', c => { out += c; });
  const exitCode = await new Promise(resolve => child.on('exit', resolve));
  await control.close();
  if (!fs.existsSync(resultsPath)) {
    throw new Error(`the ${label} run wrote no results; jasmine said:\n${out.slice(-4000)}`);
  }
  const results = JSON.parse(fs.readFileSync(resultsPath, 'utf8'));
  results.refusals = control.refusals;
  const runPath = `${resultsPath}.run.json`;
  results.run = fs.existsSync(runPath)
    ? { ...JSON.parse(fs.readFileSync(runPath, 'utf8')), exitCode }
    : { overallStatus: 'unknown', failures: [], exitCode };
  return results;
}

async function withTarget(start, fn) {
  const dbUri = `${MONGO}/parse_rust_conformance_${TAG}_${start.name}`;
  const server = await start(dbUri);
  try {
    return await fn(server);
  } finally {
    await server.stop();
    const client = await MongoClient.connect(dbUri);
    await client.db().dropDatabase();
    await client.close();
  }
}

// -------------------------------------------------------------------------------------------
// Judging
// -------------------------------------------------------------------------------------------

const problems = [];
const problem = msg => problems.push(msg);

function outcomeOf(r) {
  if (r.status === 'passed') { return 'pass'; }
  if (r.status === 'failed') { return 'fail'; }
  return 'not-run';
}

function failureClass(r, server) {
  const text = r.failures.join('\n');
  if (/ECONNREFUSED|ECONNRESET|socket hang up|XMLHttpRequest failed/i.test(text)) { return 'transport'; }
  if (/conformance: |not available in this harness/.test(text)) { return 'harness-error'; }
  if (/Internal server error|"code":1\b|code: 1\b|status(Code)?:? 500/i.test(text)) { return 'server-5xx'; }
  return 'assertion';
}

/** A reason this harness gave, or upstream's own `xit`, which is the one unexplained skip allowed. */
function notRunReason(r) {
  return r.reason || 'upstream-skipped';
}

/**
 * Every not-run reason but `upstream-skipped` must point at a register row or an upstream issue.
 *
 * - An issue is named in full, `parse-community/parse-server#NNNN`. A bare `#NNNN` is not
 *   enough: test names carry them (`regression test #1489`).
 * - A row is named as `scope exclusion: <the row's bold lead>`, and the lead must open a table row
 *   in the register (`| **<lead>**`), not merely appear somewhere in bold.
 *
 * The register is kept with the development tree, so a checkout without it can check the form
 * only. That is the public tree, and it is why exclusions are reviewed where the register is.
 */
// The register lives with the development tree and does not cross to the public one.
const REGISTER = path.join(REPO, 'docs', 'divergences.md');
const registerText = fs.existsSync(REGISTER) ? fs.readFileSync(REGISTER, 'utf8') : null;
function authorized(reason) {
  if (reason === 'upstream-skipped') { return true; }
  if (/parse-community\/parse-server#\d+/.test(reason)) { return true; }
  const row = /scope exclusion: (.+)$/.exec(reason);
  if (!row) { return false; }
  if (registerText === null) { return true; }
  return registerText.split('\n').some(line => line.startsWith(`| **${row[1]}**`));
}

function judgeRust(results, stats, server) {
  const rows = [];
  for (const r of results) {
    const known = inventory.files[r.file]?.blocks?.[r.key];
    if (!known) { problem(`[inventory] ${r.file}: an uncommitted block ran: ${r.fullName}`); continue; }
    const outcome = outcomeOf(r);
    const row = { file: r.file, key: r.key, name: r.fullName, outcome, subject: known.subject };
    if (outcome === 'not-run') {
      row.not_run_reason = notRunReason(r);
      if (!authorized(row.not_run_reason)) {
        problem(`[skip] ${r.file}: unauthorized not-run "${row.not_run_reason}": ${r.fullName}`);
      }
    }
    if (outcome === 'fail') {
      row.failure_class = failureClass(r, server);
      row.failure = r.failures[0]?.slice(0, 300);
    }
    // Condition 3, both directions, against what parse-rust itself counted.
    const seen = stats[r.key]?.body ?? 0;
    row.server_body_requests = seen;
    if (outcome === 'pass' && known.subject === 'server-dependent' && seen === 0) {
      problem(`[subject] ${r.file}: passed with no request of its own on parse-rust: ${r.fullName}`);
    }
    if (outcome !== 'not-run' && known.subject === 'client-only' && seen > 0) {
      problem(`[subject] ${r.file}: classified client-only and sent ${seen} request(s): ${r.fullName}`);
    }
    rows.push(row);
  }
  // The contract, checked against the editable inventory: every committed file is in it and in this
  // run, and no inventory floor is below the contract's. Deleting a file's entry or lowering its
  // floor in `inventory.json` would otherwise shrink the gate without anyone reviewing it.
  for (const [file, floor] of Object.entries(FLOORS)) {
    if (!inventory.files[file]) { problem(`[contract] ${file} is committed with floor ${floor} and missing from inventory.json`); continue; }
    if (!opt('--files') && !files.includes(file)) { problem(`[contract] ${file} is committed and was not in this run`); }
    if (inventory.files[file].floor < floor) {
      problem(`[contract] ${file}: inventory floor ${inventory.files[file].floor} is below the contract's ${floor}`);
    }
  }
  // Gate G condition 1: these files are green(mongo), every committed block executed and passed.
  for (const file of MUST_BE_GREEN.filter(f => files.includes(f))) {
    const mine = rows.filter(x => x.file === file);
    const bad = mine.filter(x => x.outcome !== 'pass');
    if (mine.length === 0 || bad.length) {
      problem(`[green] ${file} must be green(mongo): ${bad.length} of ${mine.length} blocks did not pass${bad[0] ? `, first: ${bad[0].name}` : ''}`);
    }
  }
  // Condition 1: executed blocks at or above each committed floor.
  for (const [file, spec] of Object.entries(inventory.files).filter(([f]) => files.includes(f))) {
    const executed = rows.filter(x => x.file === file && x.outcome !== 'not-run').length;
    if (executed < spec.floor) {
      problem(`[floor] ${file}: ${executed} blocks executed, floor is ${spec.floor}`);
    }
    const missing = Object.keys(spec.blocks).filter(k => !rows.some(x => x.key === k));
    for (const k of missing) { problem(`[inventory] ${file}: a committed block did not run: ${spec.blocks[k].name}`); }
  }
  for (const x of rows) {
    if (['transport', 'server-panic', 'harness-error'].includes(x.failure_class)) {
      problem(`[class] ${x.file}: ${x.failure_class}: ${x.name}`);
    }
  }
  if (server.panics() > 0) { problem(`[panic] parse-rust panicked ${server.panics()} time(s)`); }
  return rows;
}

function judgeDead(results) {
  const passing = new Set(results.filter(r => r.status === 'passed').map(r => r.key));
  // Client-only blocks, plus the server-dependent ones declared vacuous with no server: a block
  // that passes on any error is satisfied by a refused connection. Each declaration is committed
  // in the inventory with its reason, so the set is reviewed rather than discovered.
  const clientOnly = new Set();
  for (const [, spec] of Object.entries(inventory.files).filter(([f]) => files.includes(f))) {
    for (const [k, b] of Object.entries(spec.blocks)) {
      if (b.subject === 'client-only' || b.passes_without_server) { clientOnly.add(k); }
    }
  }
  for (const k of passing) {
    if (!clientOnly.has(k)) { problem(`[dead] passed with no server and is not client-only: ${nameOf(k)}`); }
  }
  for (const k of clientOnly) {
    if (!passing.has(k)) { problem(`[dead] client-only and did not pass with no server: ${nameOf(k)}`); }
  }
  return { passing: passing.size, clientOnly: clientOnly.size };
}

/**
 * Condition 5, the positive control. Reported failures are not enough: a run that executed nothing,
 * left blocks pending, or failed outside any block reports no failed block at all. So every block
 * the inventory records as passing upstream must be present and passed, and the run itself must be
 * clean.
 */
/**
 * Blocks whose outcome against parse-server itself depends on timing, declared with their reason
 * in `upstream-unstable.json`. They still run; a failure is printed rather than counted, because a
 * control that fails at random trains people to ignore it. An undeclared block failing is still a
 * problem, and a declaration naming no block in this run is stale.
 */
const UNSTABLE = JSON.parse(fs.readFileSync(path.join(HERE, 'upstream-unstable.json'), 'utf8'));
const isUnstable = r => Boolean(UNSTABLE[r.file]?.[r.fullName]);

function judgeUpstream(results) {
  for (const [file, blocks] of Object.entries(UNSTABLE).filter(([f]) => files.includes(f))) {
    for (const name of Object.keys(blocks)) {
      if (!results.some(r => r.file === file && r.fullName === name)) {
        problem(`[upstream] stale declaration in upstream-unstable.json: ${file}: ${name}`);
      }
    }
  }
  for (const r of results.filter(isUnstable)) {
    if (r.status === 'failed') {
      console.log(`upstream: declared unstable and failed this run: ${r.file}: ${r.fullName}`);
    }
  }
  for (const r of results.filter(x => !isUnstable(x))) {
    if (r.status === 'failed') {
      problem(`[upstream] fails against the pinned parse-server: ${r.file}: ${r.fullName}: ${r.failures[0]?.slice(0, 200)}`);
    }
  }
  const byKey = new Map(results.map(r => [r.key, r]));
  for (const [file, spec] of Object.entries(inventory.files).filter(([f]) => files.includes(f))) {
    for (const [key, block] of Object.entries(spec.blocks)) {
      if (block.upstream !== 'pass') { continue; }
      const r = byKey.get(key);
      if (r && isUnstable(r)) { continue; }
      if (!r) {
        problem(`[upstream] did not run against the pinned parse-server: ${file}: ${block.name}`);
      } else if (r.status !== 'passed' && r.status !== 'excluded' && !r.reason) {
        problem(`[upstream] ${r.status} against the pinned parse-server: ${file}: ${block.name}`);
      }
    }
  }
  for (const f of results.run?.failures || []) {
    problem(`[upstream] failure outside any block: ${f.suite}: ${String(f.message).slice(0, 200)}`);
  }
  // Jasmine's exit status counts the unstable blocks too, so it is only a problem when something
  // other than a declared unstable block failed.
  const onlyUnstable = results.every(r => r.status !== 'failed' || isUnstable(r));
  if (results.run?.exitCode !== 0 && !(onlyUnstable && results.run?.overallStatus === 'failed')) {
    problem(`[upstream] jasmine exited ${results.run?.exitCode} (${results.run?.overallStatus})`);
  }
}

function nameOf(key) {
  for (const spec of Object.values(inventory.files)) { if (spec.blocks[key]) { return spec.blocks[key].name; } }
  return key;
}

// -------------------------------------------------------------------------------------------

function writeInventory(results, hashes) {
  const pin = fs.readFileSync(path.join(REPO, 'PIN'), 'utf8').match(/^parse-server \S+ (\S+)$/m)[1];
  // Merge: classifying one file must not drop the others' committed blocks.
  const out = { pin, files: { ...(inventory?.files || {}) } };
  for (const file of files) {
    const blocks = {};
    for (const r of results.filter(x => x.file === file)) {
      const previous = inventory?.files?.[file]?.blocks?.[r.key];
      const upstream = outcomeOf(r);
      blocks[r.key] = {
        name: r.fullName,
        // Only an executed block has a subject: one that never runs sends nothing either way.
        subject: upstream === 'not-run' ? 'not-run' : r.requests.body > 0 ? 'server-dependent' : 'client-only',
        upstream,
        ...(previous?.passes_without_server ? { passes_without_server: previous.passes_without_server } : {}),
      };
    }
    const executable = Object.values(blocks).filter(b => b.upstream !== 'not-run').length;
    out.files[file] = {
      floor: inventory?.files?.[file]?.floor ?? FLOORS[file] ?? executable,
      upstream_hash: hashes[file].upstream,
      blocks,
    };
  }
  fs.writeFileSync(INVENTORY, JSON.stringify(out, null, 2) + '\n');
  console.log(`inventory written: ${files.map(f => `${f} ${Object.keys(out.files[f].blocks).length} blocks`).join(', ')}`);
}

/**
 * Gate H condition 4: the control plane's acceptance files, which reconfigure in nearly every
 * block. Not conformance rows. On parse-rust, every reconfigure carrying an option it cannot map
 * must be refused naming the option, and **no block whose reconfigure was refused may pass**,
 * because a pass there would mean the refusal was swallowed and the block measured nothing.
 * Against the pinned parse-server the same files show that the supervisor itself is faithful.
 */
/**
 * Gate H's floors, per file. `refusals` is how many reconfigures parse-rust refuses by name;
 * `upstreamPasses` is how many blocks pass against the pinned parse-server through the same
 * supervisor, which is the evidence the supervisor itself is faithful.
 */
const CONTROL_FLOORS = {
  // Re-measured once options that cannot be sent as JSON were refused by name rather than dropped:
  // the floors before that were set against a supervisor that lost them. One `index.spec.js` block
  // has varied between runs of the pinned parse-server itself, so its parse-server floor is one
  // below the measured 9; `control-plane-run.json` names the passing blocks per run so the varying
  // one can be identified by diffing two of them.
  'index.spec.js': { blocks: 53, refusals: 45, upstreamPasses: 8 },
  'PasswordPolicy.spec.js': { blocks: 42, refusals: 43, upstreamPasses: 11 },
};

async function controlPlane() {
  const rust = await withTarget(startRust, s => runSuite(s, 'control-rust'));
  const refusedBlocks = new Set(rust.refusals.map(r => r.block));
  // Blocks that expect any rejection pass on a refusal for the wrong reason. Each is declared in
  // `control-plane.json` with its reason, so the exception is a reviewed line; an undeclared one is
  // a swallowed refusal, and a declaration that no longer applies is stale.
  const declared = JSON.parse(fs.readFileSync(path.join(HERE, 'control-plane.json'), 'utf8'));
  const isDeclared = r => Boolean(declared[r.file]?.[r.fullName]);
  const passedAnyway = rust.filter(r => r.status === 'passed' && refusedBlocks.has(r.key));
  for (const r of passedAnyway.filter(r => !isDeclared(r))) {
    problem(`[control] passed although its reconfigure was refused: ${r.file}: ${r.fullName}`);
  }
  for (const [file, blocks] of Object.entries(declared)) {
    for (const name of Object.keys(blocks)) {
      if (!passedAnyway.some(r => r.file === file && r.fullName === name)) {
        problem(`[control] stale declaration in control-plane.json: ${file}: ${name}`);
      }
    }
  }
  for (const r of rust.refusals) {
    if (!/cannot map option '[^']+'|'[^']+' did not take effect|refused option '(?!unknown')[^']+' at boot/.test(r.error)) {
      problem(`[control] a refusal that does not name the option: ${r.error}`);
    }
  }
  const upstream = await withTarget(startUpstream, s => runSuite(s, 'control-upstream'));
  fs.mkdirSync(path.join(REPO, 'target/conformance'), { recursive: true });
  fs.writeFileSync(path.join(REPO, 'target/conformance/control-plane-run.json'), JSON.stringify({
    rust: rust.map(r => ({ file: r.file, name: r.fullName, status: r.status })),
    upstream: upstream.map(r => ({ file: r.file, name: r.fullName, status: r.status })),
    refusals: rust.refusals,
  }, null, 2));
  // Per file, so losing one file's blocks cannot hide behind the other's. A run that executed
  // nothing, or reconfigured nothing, must not report clean.
  for (const [file, floor] of Object.entries(CONTROL_FLOORS)) {
    if (!files.includes(file)) { continue; }
    const executed = rows => rows.filter(r => r.file === file && (r.status === 'passed' || r.status === 'failed')).length;
    const refused = rust.refusals.filter(r => rust.some(x => x.key === r.block && x.file === file)).length;
    if (executed(rust) < floor.blocks) { problem(`[control] ${file}: ${executed(rust)} blocks executed on parse-rust, floor ${floor.blocks}`); }
    if (executed(upstream) < floor.blocks) { problem(`[control] ${file}: ${executed(upstream)} blocks executed on parse-server, floor ${floor.blocks}`); }
    if (refused < floor.refusals) { problem(`[control] ${file}: ${refused} reconfigures refused, floor ${floor.refusals}`); }
    const upstreamPassed = upstream.filter(r => r.file === file && r.status === 'passed').length;
    if (upstreamPassed < floor.upstreamPasses) { problem(`[control] ${file}: ${upstreamPassed} blocks pass on parse-server, floor ${floor.upstreamPasses}`); }
  }
  const keys = [...new Set(rust.refusals.map(r => (/'([^']+)'/.exec(r.error) || [])[1]).filter(Boolean))].sort();
  console.log(`control plane: ${rust.refusals.length} reconfigures refused on parse-rust, naming ${keys.length} options: ${keys.join(', ')}`);
  console.log(`control plane: on parse-rust ${rust.filter(r => r.status === 'passed').length} of ${rust.length} blocks pass; on the pinned parse-server ${upstream.filter(r => r.status === 'passed').length} of ${upstream.length}`);
  for (const file of files) {
    const refused = rust.refusals.filter(r => rust.some(x => x.key === r.block && x.file === file)).length;
    const n = (rows, st) => rows.filter(r => r.file === file && (!st || r.status === st)).length;
    console.log(`control plane: ${file}: ${n(rust)} blocks, ${refused} refusals, ${n(upstream, 'passed')} pass on parse-server`);
  }
}

async function main() {
  const hashes = vendor();
  if (args.includes('--control-plane')) {
    await controlPlane();
    if (problems.length) {
      for (const p of problems) { console.error(`  - ${p}`); }
      process.exit(1);
    }
    console.log('gate H condition 4: clean');
    return;
  }
  if (classify) {
    const results = await withTarget(startUpstream, s => runSuite(s, 'classify'));
    writeInventory(results, hashes);
    return;
  }
  if (!inventory) { console.error('no inventory.json; run with --classify first'); process.exit(2); }
  for (const file of files) {
    if (inventory.files[file]?.upstream_hash !== hashes[file].upstream) {
      problem(`[inventory] ${file} changed upstream since the inventory was committed; re-classify`);
    }
  }
  const report = { tag: TAG, hashes };
  if (target === 'rust' || target === 'all') {
    report.rust = await withTarget(startRust, async s => judgeRust(await runSuite(s, 'rust'), await s.stats(), s));
  }
  if (target === 'dead' || target === 'all') {
    report.dead = await withTarget(startDead, async s => judgeDead(await runSuite(s, 'dead')));
  }
  if (target === 'upstream' || target === 'all') {
    await withTarget(startUpstream, async s => judgeUpstream(await runSuite(s, 'upstream')));
  }
  // The report records what ran and whether the judges passed, so the status generator can refuse
  // a run that failed its controls or skipped them. A status is a claim the controls stand behind.
  report.targets = target;
  report.complete = target === 'all' && !opt('--files');
  report.problems = problems.slice();
  fs.mkdirSync(path.join(REPO, 'target/conformance'), { recursive: true });
  fs.writeFileSync(path.join(REPO, 'target/conformance/report.json'), JSON.stringify(report, null, 2));

  if (report.rust) {
    for (const file of files) {
      const rows = report.rust.filter(x => x.file === file);
      const n = k => rows.filter(x => x.outcome === k).length;
      console.log(`${file}: pass ${n('pass')}, fail ${n('fail')}, not-run ${n('not-run')}`);
    }
  }
  if (report.dead) { console.log(`dead-server control: ${report.dead.passing} passed, ${report.dead.clientOnly} committed client-only`); }
  if (problems.length) {
    console.error(`gate F: ${problems.length} problem(s)`);
    for (const p of problems.slice(0, 60)) { console.error(`  - ${p}`); }
    process.exit(1);
  }
  if (!report.complete) {
    // Conditions 4 and 5 need the dead-server and oracle runs, and the contract needs every file.
    // A partial run is a diagnostic.
    console.log(`gate F: partial run (--target ${target}${opt('--files') ? ', --files' : ''}), no problems in what ran; not a gate result`);
    return;
  }
  console.log('gate F: clean');
}

main().catch(e => { console.error(e); process.exit(1); });
