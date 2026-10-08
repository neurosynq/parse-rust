'use strict';
/*
 * The conformance harness's replacement for upstream's `spec/helper.js`.
 *
 * Same globals the target spec files read, and three things upstream's helper does not do:
 *
 *   1. **It starts no server.** Upstream's helper boots a parse-server in this process. Here the
 *      server is whatever `CONFORMANCE_SERVER_URL` names, started by `run.mjs` in another process.
 *      Nothing in this file requires `../lib/index`, so there is no in-process server for a request
 *      to reach by accident. A suite that quietly ran against an in-process server would report
 *      upstream's results as parse-rust's, which is the first thing this harness has to rule out.
 *   2. **Every request carries its block and phase**, in `X-Parse-Conformance-Block`, set through
 *      the SDK's `REQUEST_HEADERS` and through the `../lib/request` wrapper.
 *   3. **It writes a result per block** to `CONFORMANCE_RESULTS`, with the client-side request
 *      count the server-side count is checked against.
 *
 * Everything else is ported from `spec/helper.js` at the pin, line for line where it is used.
 */

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const PS_ROOT = process.env.PS_ROOT;
const Parse = require(path.join(PS_ROOT, 'node_modules/parse/node'));

const SERVER_URL = process.env.CONFORMANCE_SERVER_URL;
const RESULTS = process.env.CONFORMANCE_RESULTS;
const EXCLUSIONS = JSON.parse(fs.readFileSync(process.env.CONFORMANCE_EXCLUSIONS, 'utf8'));
if (!SERVER_URL || !RESULTS) {
  throw new Error('conformance/helper.js: CONFORMANCE_SERVER_URL and CONFORMANCE_RESULTS are required');
}
global.CONFORMANCE_SERVER_URL = SERVER_URL;

jasmine.DEFAULT_TIMEOUT_INTERVAL = Number(process.env.PARSE_SERVER_TEST_TIMEOUT || 10000);

// -------------------------------------------------------------------------------------------
// Block identity and phase
// -------------------------------------------------------------------------------------------

/** A stable key for a block: the spec file and its full name, hashed. Order-independent. */
function blockKey(file, fullName) {
  return crypto.createHash('sha1').update(`${file}\n${fullName}`).digest('hex').slice(0, 16);
}

let current = null; // { key, file, fullName, requests: {body, lifecycle} }
let phase = 'lifecycle';

function setPhase(p) {
  phase = p;
  Parse.CoreManager.set('REQUEST_HEADERS', {
    'X-Parse-Conformance-Block': `${current ? current.key : 'none'};${phase}`,
  });
}
global.__conformanceTag = () => `${current ? current.key : 'none'};${phase}`;
function countRequest() {
  if (current) { current.requests[phase === 'body' ? 'body' : 'lifecycle'] += 1; }
}
global.__conformanceCount = countRequest;

// Upstream's `normalizeAsyncTests` (`spec/support/CurrentSpecReporter.js:61-98`), with the phase
// set on entry. A hook is lifecycle traffic and an `it` body is the block's own.
function wrapFn(fn, ph) {
  if (typeof fn !== 'function') { return fn; }
  if (fn.length > 0) {
    return function () {
      setPhase(ph);
      return new Promise(resolve => { fn.call(this, resolve); });
    };
  }
  return function () {
    setPhase(ph);
    return fn.call(this);
  };
}
// Which spec file declared each block. Jasmine records the file that called `it`, which after
// the wrapping below is this one, so the declaring file is read off the stack instead.
const declaredIn = new Map();
function callerFile() {
  const frames = (new Error().stack || '').split('\n').slice(1);
  for (const frame of frames) {
    const m = /\(?([^()\s]+\.spec\.js):\d+:\d+\)?$/.exec(frame.trim());
    if (m) { return path.basename(m[1]); }
  }
  return '';
}
function wrapGlobal(name, ph) {
  const original = global[name];
  global[name] = function (descriptionOrFn, fn, timeout) {
    const args = Array.from(arguments);
    if (typeof descriptionOrFn === 'function') {
      args[0] = wrapFn(descriptionOrFn, ph);
    } else if (typeof fn === 'function') {
      args[1] = ph === 'body' ? wrapBody(fn) : wrapFn(fn, ph);
    }
    const spec = original.apply(this, args);
    if (ph === 'body' && spec && spec.id) { declaredIn.set(spec.id, callerFile()); }
    return spec;
  };
}
// A block named in `exclusions.json` is marked pending before its body runs, with the reason, so
// it sends nothing and reports `not-run` rather than failing.
function wrapBody(fn) {
  const wrapped = wrapFn(fn, 'body');
  return function () {
    const reason = current && EXCLUSIONS[current.file]?.[current.fullName];
    if (reason) {
      pending(`not-run: ${reason}`);
      return undefined;
    }
    return wrapped.call(this);
  };
}
wrapGlobal('it', 'body');
wrapGlobal('fit', 'body');
for (const hook of ['beforeEach', 'afterEach', 'beforeAll', 'afterAll']) { wrapGlobal(hook, 'lifecycle'); }

// The SDK's transport, counted. `REQUEST_HEADERS` carries the tag; this counts what was sent.
// `request` rather than `ajax`, because the SDK's `request` calls its own module's `ajax` directly
// and a wrapped `ajax` on the controller object is never reached.
const RESTController = Parse.CoreManager.getRESTController();
Parse.CoreManager.setRESTController({
  ...RESTController,
  request(...args) {
    countRequest();
    return RESTController.request(...args);
  },
});

// -------------------------------------------------------------------------------------------
// Results
// -------------------------------------------------------------------------------------------

const results = [];
const suiteFailures = [];
jasmine.getEnv().addReporter({
  specStarted(spec) {
    const file = declaredIn.get(spec.id) || path.basename(spec.filename || '');
    current = {
      key: blockKey(file, spec.fullName), file, fullName: spec.fullName,
      requests: { body: 0, lifecycle: 0 },
    };
    setPhase('lifecycle');
  },
  specDone(result) {
    const pendingReason = result.pendingReason || '';
    const excludedHere = pendingReason.startsWith('not-run: ');
    const reason = excludedHere ? pendingReason.replace(/^not-run: /, '') : '';
    results.push({
      key: current.key,
      file: current.file,
      fullName: result.fullName,
      status: result.status, // passed, failed, pending, excluded
      reason,
      failures: (result.failedExpectations || []).map(f => f.message).slice(0, 3),
      requests: current.requests,
    });
    current = null;
    setPhase('lifecycle');
  },
  // Failures that belong to no block: an `afterAll` that threw, a suite that could not load. They
  // fail nothing per block, so they are written beside the results for the judges to see.
  suiteDone(result) {
    for (const f of result.failedExpectations || []) {
      suiteFailures.push({ suite: result.fullName, message: f.message });
    }
  },
  jasmineDone(result) {
    fs.writeFileSync(RESULTS, JSON.stringify(results, null, 2));
    fs.writeFileSync(`${RESULTS}.run.json`, JSON.stringify({
      overallStatus: result.overallStatus,
      incompleteReason: result.incompleteReason || null,
      failures: [...suiteFailures, ...(result.failedExpectations || []).map(f => ({ suite: 'top level', message: f.message }))],
    }, null, 2));
  },
});

// -------------------------------------------------------------------------------------------
// Per-block isolation, as upstream's `afterEach` does it
// -------------------------------------------------------------------------------------------

beforeAll(async () => {
  Parse.initialize('test', 'test', 'test');
  Parse.serverURL = SERVER_URL;
  Parse.User.enableUnsafeCurrentUser();
  // `REQUEST_ATTEMPT_LIMIT = 1` disables SDK retries, so a transient failure fails the block
  // rather than being retried into a pass (`spec/helper.js:236-238`).
  Parse.CoreManager.set('REQUEST_ATTEMPT_LIMIT', 1);
});

afterEach(async () => {
  await Parse.User.logOut().catch(() => {});
  // Upstream's `destroyAllDataPermanently(true)`: every collection emptied, indexes kept.
  const reset = await fetch(process.env.CONFORMANCE_RESET_URL, { method: 'POST' });
  if (!reset.ok) { throw new Error(`reset failed: ${reset.status} ${await reset.text()}`); }
});

// -------------------------------------------------------------------------------------------
// Globals, from `spec/helper.js:296-485` at the pin
// -------------------------------------------------------------------------------------------

const TestObject = Parse.Object.extend({ className: 'TestObject' });
const Item = Parse.Object.extend({ className: 'Item' });
const Container = Parse.Object.extend({ className: 'Container' });
function create(options, callback) { return new TestObject(options).save().then(callback); }
function createTestUser() {
  const user = new Parse.User();
  user.set('username', 'test');
  user.set('password', 'moon-y');
  return user.signUp();
}
function ok(bool, message) { expect(bool).toBeTruthy(message); }
function equal(a, b, message) { expect(a).toEqual(b, message); }
function strictEqual(a, b, message) { expect(a).toBe(b, message); }
function notEqual(a, b, message) { expect(a).not.toEqual(b, message); }
function arrayContains(arr, item) { return -1 != arr.indexOf(item); }
function normalize(obj) {
  if (obj === null || typeof obj !== 'object') { return JSON.stringify(obj); }
  if (Array.isArray(obj)) { return '[' + obj.map(normalize).join(', ') + ']'; }
  let answer = '{';
  for (const key of Object.keys(obj).sort()) { answer += key + ': ' + normalize(obj[key]) + ', '; }
  return answer + '}';
}
function jequal(o1, o2) { expect(normalize(o1)).toEqual(normalize(o2)); }
function range(n) { const answer = []; for (let i = 0; i < n; i++) { answer.push(i); } return answer; }

global.Parse = Parse;
Object.assign(global, {
  TestObject, Item, Container, create, createTestUser, ok, equal, strictEqual, notEqual,
  arrayContains, jequal, range,
});
global.jfail = err => fail(JSON.stringify(err));

// The database gates. parse-rust has one backend, Mongo, which is upstream's default.
const db = process.env.PARSE_SERVER_TEST_DB || 'mongo';
global.on_db = (name, callback, elseCallback) => (name === db ? callback() : elseCallback?.());
global.it_only_db = name => (name === db ? it : xit);
global.it_exclude_dbs = excluded => (excluded.includes(process.env.PARSE_SERVER_TEST_DB) ? xit : it);
global.describe_only_db = name => (name === db ? describe : xdescribe);
global.it_id = () => testFunc => testFunc;

// `reconfigureServer`, through `run.mjs`'s supervisor, which respawns the server with the options
// mapped or refuses naming the key it cannot map (0.3.0 Gate H). A rejection carries the
// supervisor's message, so `expectAsync(reconfigureServer(...)).toBeRejectedWith(...)` sees it.
let didChangeConfiguration = false;

/**
 * Options as JSON, without losing any. `JSON.stringify` drops a function, turns a RegExp or an
 * adapter instance into `{}`, and the supervisor would then see an empty object where a key was,
 * refusing nothing. Each such value is replaced by a marker the supervisor refuses by name.
 * `undefined` is left to drop, because an unset option and an absent one are the same option.
 */
function transportable(value) {
  if (typeof value === 'function') { return { __unserializable: 'function' }; }
  if (value === null || typeof value !== 'object') { return value; }
  if (Array.isArray(value)) { return value.map(transportable); }
  const proto = Object.getPrototypeOf(value);
  if (proto !== Object.prototype && proto !== null) {
    return { __unserializable: value.constructor?.name || 'object' };
  }
  return Object.fromEntries(Object.entries(value).map(([k, v]) => [k, transportable(v)]));
}

global.reconfigureServer = async (changedConfiguration = {}) => {
  // Set before the attempt, as upstream's helper sets it (`spec/helper.js:200`), so a reconfigure
  // that fails part-way is still reverted after the block.
  didChangeConfiguration = Object.keys(changedConfiguration).length !== 0;
  const response = await fetch(process.env.CONFORMANCE_SUPERVISOR_URL, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'X-Parse-Conformance-Block': global.__conformanceTag() },
    body: JSON.stringify({ options: transportable(changedConfiguration) }),
  });
  const body = await response.json();
  // Refused or not, the server may now be at a new address; follow it before reporting either.
  if (body.url) {
    global.CONFORMANCE_SERVER_URL = body.url;
    Parse.serverURL = body.url;
  }
  if (body.reset) { process.env.CONFORMANCE_RESET_URL = body.reset; }
  if (!response.ok) { throw body.error; }
  global.CONFORMANCE_SERVER_URL = body.url;
  process.env.CONFORMANCE_RESET_URL = body.reset;
  Parse.serverURL = body.url;
  return body;
};
afterEach(async () => {
  if (didChangeConfiguration) {
    didChangeConfiguration = false;
    await global.reconfigureServer();
  }
});

// Not provided, deliberately: a spec that needs one of these is outside the target set, and an
// undefined global fails it loudly rather than quietly reaching a server this file did not start.
for (const name of ['databaseAdapter', 'defaultConfiguration', 'mockFetch']) {
  Object.defineProperty(global, name, {
    get() { throw new Error(`conformance: ${name} is not available in this harness`); },
    configurable: true,
  });
}
