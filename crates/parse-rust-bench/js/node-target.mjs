/*
 * The `node` benchmark target: parse-server at the pin, with the same database-time headers the
 * parse-rust benchmark build emits (`X-Bench-Db-Micros`, `X-Bench-Db-Ops`, `X-Bench-Db-Shape`).
 *
 * The boundary is the same as the parse-rust side's: the driver's command monitoring, a command's interval from `commandStarted` to `commandSucceeded` or
 * `commandFailed`, **attributed at `commandStarted`** through an `AsyncLocalStorage` context the
 * request middleware establishes, and **closed by `requestId`**, not by whatever context is current
 * when it completes. Commands with no request context, heartbeats and handshakes, belong to no
 * request. Overlapping commands count as a union of intervals. Pool wait is outside a command's
 * interval here as it is on the parse-rust side.
 *
 * Environment: PS_ROOT, BENCH_DB_URI, BENCH_APP_ID, BENCH_MASTER_KEY, BENCH_PORT (0 for any).
 * Prints `NODE-TARGET {"url":...}` once listening.
 */
import { AsyncLocalStorage } from 'node:async_hooks';
import { createRequire } from 'node:module';

const PS_ROOT = process.env.PS_ROOT;
const require = createRequire(`${PS_ROOT}/`);
const { ParseServer } = require(`${PS_ROOT}/lib/index.js`);
const Config = require(`${PS_ROOT}/lib/Config`);

const als = new AsyncLocalStorage();
const inFlight = new Map();
let unattributed = 0;

function skeleton(v) {
  if (v === null) { return 'null'; }
  if (Array.isArray(v)) { return `[${v.map(skeleton).join(',')}]`; }
  if (v instanceof Date) { return 'datetime'; }
  if (typeof v === 'object') {
    if (v._bsontype) { return String(v._bsontype).toLowerCase(); }
    return `{${Object.entries(v).map(([k, x]) => `${k}:${skeleton(x)}`).join(',')}}`;
  }
  if (typeof v === 'number') { return Number.isInteger(v) ? 'int32' : 'double'; }
  return typeof v;
}

/** The driver builds `sort` as a `Map`, which `JSON.stringify` writes as `{}`. */
function plain(v) {
  if (v instanceof Map) { return Object.fromEntries([...v].map(([k, x]) => [k, plain(x)])); }
  if (Array.isArray(v)) { return v.map(plain); }
  if (v && typeof v === 'object' && !v._bsontype) {
    return Object.fromEntries(Object.entries(v).map(([k, x]) => [k, plain(x)]));
  }
  return v;
}

function shapeOf(name, command) {
  const collection = typeof command[name] === 'string' ? command[name] : '';
  const statement = (command.updates || command.deletes || [])[0];
  const filter = command.filter ?? command.q ?? command.query ?? command.pipeline
    ?? statement?.q ?? statement?.filter;
  let out = `${name} ${collection} ${filter === undefined ? '' : skeleton(filter)}`;
  // The options that change what the command does, verbatim, in the same order as the Rust side:
  // a fixture that ignored them would not notice a lost projection or a reversed sort.
  for (const key of ['projection', 'sort', 'limit', 'skip', 'hint']) {
    if (command[key] !== undefined) { out += ` ${key}=${JSON.stringify(plain(command[key]))}`; }
  }
  return out;
}

function unionMicros(intervals) {
  const sorted = [...intervals].sort((a, b) => (a[0] < b[0] ? -1 : 1));
  let total = 0n;
  let cur = null;
  for (const [s, e] of sorted) {
    if (cur && s <= cur[1]) { cur[1] = e > cur[1] ? e : cur[1]; continue; }
    if (cur) { total += cur[1] - cur[0]; }
    cur = [s, e];
  }
  if (cur) { total += cur[1] - cur[0]; }
  return Number(total / 1000n);
}

const server = await ParseServer.startApp({
  appId: process.env.BENCH_APP_ID,
  masterKey: process.env.BENCH_MASTER_KEY,
  databaseURI: process.env.BENCH_DB_URI,
  databaseOptions: { monitorCommands: true },
  mountPath: '/parse',
  host: '127.0.0.1',
  port: Number(process.env.BENCH_PORT || 0),
  serverURL: 'http://127.0.0.1/parse',
  allowClientClassCreation: true,
  allowCustomObjectId: true,
  directAccess: false,
  silent: true,
  // Runs before Parse's routes. The context it opens is the one every command the request issues
  // is attributed to, and the headers are written just before the response's own.
  middleware: (req, res, next) => {
    const tally = { intervals: [], ops: 0, shapes: [] };
    const writeHead = res.writeHead;
    res.writeHead = function (...args) {
      res.setHeader('X-Bench-Db-Micros', String(unionMicros(tally.intervals)));
      res.setHeader('X-Bench-Db-Ops', String(tally.ops));
      res.setHeader('X-Bench-Db-Shape', JSON.stringify(tally.shapes));
      return writeHead.apply(this, args);
    };
    als.run(tally, next);
  },
});

const client = Config.get(process.env.BENCH_APP_ID).database.adapter.client;
client.on('commandStarted', ev => {
  const tally = als.getStore();
  if (!tally) { unattributed += 1; return; }
  tally.ops += 1;
  tally.shapes.push(shapeOf(ev.commandName, ev.command));
  inFlight.set(ev.requestId, { tally, start: process.hrtime.bigint() });
});
const close = ev => {
  const entry = inFlight.get(ev.requestId);
  if (!entry) { return; }
  inFlight.delete(ev.requestId);
  entry.tally.intervals.push([entry.start, process.hrtime.bigint()]);
};
client.on('commandSucceeded', close);
client.on('commandFailed', close);
server.expressApp.get('/_bench/unattributed', (_req, res) => res.json({ unattributed }));

console.log(`NODE-TARGET ${JSON.stringify({ url: `http://127.0.0.1:${server.server.address().port}/parse` })}`);
