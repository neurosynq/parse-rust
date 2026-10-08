#!/usr/bin/env node
/*
 * Oracle for the `_SCHEMA` storage format.
 *
 * Boots real parse-server, writes one object containing every field type parse-rust supports, and
 * dumps the resulting `_SCHEMA` document straight out of MongoDB with the raw driver.
 *
 * `_SCHEMA` is shared with any parse-server reading the same database, and both of its failure
 * modes are silent: an unknown key is read as a phantom field, and an unknown type string falls
 * off the end of a `switch` with no default case and becomes `undefined`. So the strings are not
 * checked by reading the source, they are checked against what the real server writes.
 *
 * Prints the schema document as JSON on stdout. The Rust side compares.
 */
'use strict';

// Resolve the parse-server checkout relative to this repository rather than to a home directory,
// so the default works for anyone with the two repos side by side. Override with
// PARSE_SERVER_ROOT when it lives elsewhere.
// Resolved absolutely, override included: `require` reads a relative specifier against this
// file's directory, so `../parse-server-pinned` was looked for inside `tools/`.
const PS_ROOT = require('path').resolve(
  __dirname, '..', process.env.PARSE_SERVER_ROOT || '../parse-server',
);

const { ParseServer } = require(`${PS_ROOT}/lib/index.js`);
const Parse = require(`${PS_ROOT}/node_modules/parse/node`);
const { MongoClient } = require(`${PS_ROOT}/node_modules/mongodb`);

// Ephemeral port: several test batteries may run at once.
const PORT = 0;
const DB = `schemafmt_${process.pid}`;
const URI = `${process.env.PARSE_RUST_TEST_MONGO || 'mongodb://127.0.0.1:27017'}/${DB}`;

async function main() {
  const server = await ParseServer.startApp({
    appId: 'schemafmt',
    masterKey: 'schemafmt',
    databaseURI: URI,
    serverURL: 'http://127.0.0.1/parse',
    mountPath: '/parse',
    port: PORT,
    silent: true,
    allowClientClassCreation: true,
  });
  const bound = server.server.address().port;

  Parse.initialize('schemafmt', null, 'schemafmt');
  Parse.serverURL = `http://127.0.0.1:${bound}/parse`;

  const target = new Parse.Object('Target');
  await target.save(null, { useMasterKey: true });

  const obj = new Parse.Object('FormatProbe');
  obj.set('aString', 'x');
  obj.set('aNumber', 1.5);
  obj.set('aBoolean', true);
  obj.set('aDate', new Date('2026-01-01T00:00:00.000Z'));
  obj.set('anArray', [1, 2]);
  obj.set('anObject', { k: 'v' });
  obj.set('aGeoPoint', new Parse.GeoPoint(1, 2));
  obj.set('aPointer', target);
  obj.set('aFile', new Parse.File('f.txt', [1, 2, 3]));
  obj.set('aPolygon', new Parse.Polygon([[0, 0], [1, 0], [1, 1], [0, 0]]));
  obj.set('someBytes', { __type: 'Bytes', base64: 'aGVsbG8=' });
  const rel = obj.relation('aRelation');
  rel.add(target);
  await obj.save(null, { useMasterKey: true });

  const client = await MongoClient.connect(URI);
  const schema = await client.db(DB).collection('_SCHEMA').findOne({ _id: 'FormatProbe' });
  await client.db(DB).dropDatabase();
  await client.close();

  // Prefixed, because parse-server writes warnings to stdout and a bare JSON line cannot be
  // told apart from them by a consumer.
  console.log(`SCHEMA_JSON ${JSON.stringify(schema)}`);
  process.exit(0);
}

main().catch(e => {
  console.error(e && e.message ? e.message : e);
  process.exit(1);
});
