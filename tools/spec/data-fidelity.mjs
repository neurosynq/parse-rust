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
  console.error('usage: node tools/spec/data-fidelity.mjs <parse-rust-url> <mongo-uri> [appId] [masterKey]');
  process.exit(2);
}

// A floor, because a check that can pass by finding nothing will. A direction that throws early,
// or a field list emptied in a refactor, lands below this and fails rather than reporting a green
// suite. Raise it when assertions are added; never lower it to make a run pass.
const ASSERTION_FLOOR = 68;

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

/**
 * The values under test. Every 0.1.0 field type plus the number boundaries, and the three types
 * whose **stored form is ambiguous**.
 *
 * GeoPoint, Polygon and Bytes are stored as an ordinary array, an ordinary document and BSON
 * Binary, so nothing about the stored value says what it was: only the declared type in `_SCHEMA`
 * distinguishes a GeoPoint from a two-element array. That makes them the exact types a read path
 * can silently get wrong, and they were the ones this gate did not cover. parse-rust returned a
 * bare `[2, 1]` for a saved GeoPoint and every assertion here passed.
 */
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
    aGeoPoint: new Parse.GeoPoint(41.878, -87.629),
    // Three distinct vertices is the minimum `PolygonCoder` accepts.
    aPolygon: new Parse.Polygon([[0, 0], [0, 1], [1, 1], [1, 0]]),
    aBytes: { __type: 'Bytes', base64: 'aGVsbG8=' },
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
  // **Asserted as the type, not just as the value.** `obj.get('aGeoPoint')` compares equal to a
  // plain array under a loose check, so the class is the assertion that has teeth: a read path that
  // never consulted the schema hands back an Array here and an Object for the polygon.
  check(`${who}: geopoint is a Parse.GeoPoint`, obj.get('aGeoPoint') instanceof Parse.GeoPoint);
  eq(`${who}: geopoint latitude`, obj.get('aGeoPoint')?.latitude, 41.878);
  eq(`${who}: geopoint longitude`, obj.get('aGeoPoint')?.longitude, -87.629);
  check(`${who}: polygon is a Parse.Polygon`, obj.get('aPolygon') instanceof Parse.Polygon);
  // The ring read back carries the closing vertex that the write appended, so it is one longer
  // than what was sent. That is upstream's shape and the point of comparing against it.
  eq(`${who}: polygon coordinates`,
    JSON.stringify(obj.get('aPolygon')?.coordinates),
    JSON.stringify([[0, 0], [0, 1], [1, 1], [1, 0], [0, 0]]));
  eq(`${who}: bytes`,
    JSON.stringify(obj.get('aBytes')),
    JSON.stringify({ __type: 'Bytes', base64: 'aGVsbG8=' }));
  check(`${who}: createdAt is a real date`,
    obj.createdAt instanceof Date && !Number.isNaN(obj.createdAt.getTime()));
}

async function main() {
  // Boot upstream against the same database parse-rust is using.
  //
  // **`directAccess: false` is what makes this gate bidirectional.** It defaults to `true`
  // (`Options/Definitions.js:191-196`), and when it is on, `startApp` replaces the SDK's REST
  // controller with an in-process router (`ParseServer.ts:370-372`). Every SDK call in this
  // process then reaches upstream whatever `Parse.serverURL` says, so the "parse-rust writes"
  // direction silently becomes a second upstream write and the gate compares parse-server against
  // itself. It passes, and it measures nothing.
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
    'aGeoPoint', 'aPolygon', 'aBytes',
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
      // The declared types that make the three ambiguous columns readable at all.
      ['aGeoPoint', 'geopoint'], ['aPolygon', 'polygon'], ['aBytes', 'bytes'],
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
  if (passed < ASSERTION_FLOOR) {
    console.error(`FAIL  data-fidelity ran ${passed} assertions, floor is ${ASSERTION_FLOOR}`);
    process.exit(1);
  }
  console.log(`OK  data-fidelity: ${passed} assertions pass in both directions`);
  process.exit(0);
}

main().catch(e => {
  console.error('harness error:', e && e.message ? e.message : e);
  process.exit(2);
});
