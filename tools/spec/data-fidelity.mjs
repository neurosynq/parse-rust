/*
 * Gate B of the 0.1.0 milestone: bidirectional data fidelity on one database.
 *
 * This is the gate that earns the words "for MongoDB". Gate A only shows that parse-rust is
 * self-consistent; this shows that the rows it writes are the rows parse-server reads, and the
 * reverse, against the same collection and the same `_SCHEMA`.
 *
 * It boots a real parse-server itself, pointed at whatever database parse-rust is using, and
 * drives both through their REST APIs with the unmodified SDK.
 *
 * Usage:
 *   node tools/spec/data-fidelity.mjs <parse-rust-url> <mongo-uri> [appId] [masterKey]
 */

import { createRequire } from 'node:module';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const require = createRequire(import.meta.url);
// Resolve the parse-server checkout relative to this repository rather than to a home directory,
// so the default works for anyone with the two repos side by side. Override with
// PARSE_SERVER_ROOT when it lives elsewhere.
const PS_ROOT = process.env.PARSE_SERVER_ROOT
  || path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..', '..', 'parse-server');
const { ParseServer } = require(`${PS_ROOT}/lib/index.js`);
const Parse = require(`${PS_ROOT}/node_modules/parse/node`);
const { MongoClient } = require(`${PS_ROOT}/node_modules/mongodb`);

const [, , RUST_URL, MONGO_URI, APP_ID = 'test', MASTER_KEY = 'test'] = process.argv;
if (!RUST_URL || !MONGO_URI) {
  console.error('usage: node tools/spec/data-fidelity.mjs <parse-rust-url> <mongo-uri> [appId] [masterKey]');
  process.exit(2);
}

let passed = 0;
const failures = [];
function check(name, cond, detail = '') {
  if (cond) { passed++; } else { failures.push(`${name}${detail ? `: ${detail}` : ''}`); }
}
function eq(name, actual, expected) {
  check(name, actual === expected,
    `expected ${JSON.stringify(expected)}, got ${JSON.stringify(actual)}`);
}

const CLASS = `Fidelity${process.pid}`;
const ISO = '2026-08-14T13:34:33.581Z';

/** The values under test. Chosen to cover every 0.1.0 field type plus the number boundaries. */
function payload(marker) {
  return {
    marker,
    aString: 'hello',
    aBoolean: true,
    anInt: 7,
    aNegativeInt: -42,
    anI32Max: 2147483647,
    aBeyondI32: 2147483648,
    aFraction: 1.5,
    aBigFloat: 1e20,
    aZero: 0,
    aDate: new Date(ISO),
    anArray: [1, 'two', false],
    anObject: { k: 'v', n: 3 },
  };
}

/** Read a saved object back through a given serverURL and return its plain values. */
async function readBack(serverURL, marker) {
  Parse.serverURL = serverURL;
  const q = new Parse.Query(CLASS);
  q.equalTo('marker', marker);
  const [obj] = await q.find({ useMasterKey: true });
  return obj;
}

function assertValues(who, obj) {
  check(`${who}: object came back`, !!obj);
  if (!obj) { return; }
  eq(`${who}: string`, obj.get('aString'), 'hello');
  eq(`${who}: boolean`, obj.get('aBoolean'), true);
  eq(`${who}: int`, obj.get('anInt'), 7);
  eq(`${who}: negative int`, obj.get('aNegativeInt'), -42);
  eq(`${who}: i32 max`, obj.get('anI32Max'), 2147483647);
  eq(`${who}: beyond i32`, obj.get('aBeyondI32'), 2147483648);
  eq(`${who}: fraction`, obj.get('aFraction'), 1.5);
  eq(`${who}: big float`, obj.get('aBigFloat'), 1e20);
  eq(`${who}: zero`, obj.get('aZero'), 0);
  check(`${who}: date is a Date`, obj.get('aDate') instanceof Date);
  eq(`${who}: date value`, obj.get('aDate')?.toISOString(), ISO);
  eq(`${who}: array`, JSON.stringify(obj.get('anArray')), JSON.stringify([1, 'two', false]));
  eq(`${who}: object`, JSON.stringify(obj.get('anObject')), JSON.stringify({ k: 'v', n: 3 }));
  check(`${who}: createdAt is a real date`,
    obj.createdAt instanceof Date && !Number.isNaN(obj.createdAt.getTime()));
}

async function main() {
  // Boot upstream against the same database parse-rust is using.
  const upstream = await ParseServer.startApp({
    appId: APP_ID,
    masterKey: MASTER_KEY,
    databaseURI: MONGO_URI,
    serverURL: 'http://127.0.0.1/parse',
    mountPath: '/parse',
    port: 0,
    silent: true,
    allowClientClassCreation: true,
  });
  const upstreamUrl = `http://127.0.0.1:${upstream.server.address().port}/parse`;

  Parse.initialize(APP_ID, undefined, MASTER_KEY);

  // --- direction 1: parse-rust writes, parse-server reads -----------------
  Parse.serverURL = RUST_URL;
  const fromRust = new Parse.Object(CLASS);
  fromRust.set(payload('written-by-rust'));
  await fromRust.save(null, { useMasterKey: true });

  assertValues('rust -> parse-server', await readBack(upstreamUrl, 'written-by-rust'));

  // --- direction 2: parse-server writes, parse-rust reads -----------------
  Parse.serverURL = upstreamUrl;
  const fromUpstream = new Parse.Object(CLASS);
  fromUpstream.set(payload('written-by-upstream'));
  await fromUpstream.save(null, { useMasterKey: true });

  assertValues('parse-server -> rust', await readBack(RUST_URL, 'written-by-upstream'));

  // --- the stored BSON types must match, not just the values --------------
  // This is where the Int32-versus-Double rule either holds or silently corrupts data. Values
  // alone would not catch it, because both types read back as the same JavaScript number.
  const client = await MongoClient.connect(MONGO_URI);
  const db = client.db(MONGO_URI.split('/').pop());
  const [rustDoc, upstreamDoc] = await Promise.all([
    db.collection(CLASS).findOne({ marker: 'written-by-rust' }, { promoteValues: false }),
    db.collection(CLASS).findOne({ marker: 'written-by-upstream' }, { promoteValues: false }),
  ]);

  const typeOf = v => (v && v._bsontype) ? v._bsontype
    : (typeof v === 'number' ? (Number.isInteger(v) ? 'Int32?' : 'Double?') : typeof v);

  for (const field of [
    'anInt', 'aNegativeInt', 'anI32Max', 'aBeyondI32', 'aFraction', 'aBigFloat', 'aZero',
    'aString', 'aBoolean', 'aDate', 'anArray', 'anObject',
  ]) {
    eq(`stored BSON type of ${field}`, typeOf(rustDoc?.[field]), typeOf(upstreamDoc?.[field]));
  }

  // --- the two servers must agree on the schema ---------------------------
  const schema = await db.collection('_SCHEMA').findOne({ _id: CLASS });
  check('a single _SCHEMA document exists for the class', !!schema);
  if (schema) {
    for (const [field, expected] of [
      ['aString', 'string'], ['aBoolean', 'boolean'], ['anInt', 'number'],
      ['aDate', 'date'], ['anArray', 'array'], ['anObject', 'object'],
    ]) {
      eq(`_SCHEMA ${field}`, schema[field], expected);
    }
    check('_SCHEMA carries no ACL key', !('ACL' in schema));
  }

  await db.dropDatabase();
  await client.close();

  if (failures.length) {
    console.error(`FAIL  ${failures.length} assertion(s):`);
    for (const f of failures) { console.error(`  - ${f}`); }
    process.exit(1);
  }
  console.log(`OK  data-fidelity: ${passed} assertions pass in both directions`);
  process.exit(0);
}

main().catch(e => {
  console.error('harness error:', e && e.message ? e.message : e);
  process.exit(2);
});
