#!/usr/bin/env node
/*
 * Differential oracle for the Parse/BSON transform.
 *
 * `MongoTransform.js` exports `parseObjectToMongoObjectForCreate` and `mongoObjectToParseObject`,
 * so this compares against the real function rather than against a reading of it. Both sides emit
 * canonical Extended JSON, which is what makes BSON *type* differences visible: Int32 and Double
 * both print as a bare number in ordinary JSON, and the whole point of the exercise is that they
 * are not the same.
 *
 * Reads a JSON array of cases on stdin:
 *   [{ name, className, schema, object, rustBson }]
 * where `rustBson` is our transform's output as canonical Extended JSON.
 *
 * Exits non-zero on the first divergence, printing both sides.
 */
'use strict';

// Resolve the parse-server checkout relative to this repository rather than to a home directory,
// so the default works for anyone with the two repos side by side. Override with
// PARSE_SERVER_ROOT when it lives elsewhere.
const PS_ROOT = process.env.PARSE_SERVER_ROOT
  || require('path').resolve(__dirname, '..', '..', 'parse-server');

const MongoTransform = require(`${PS_ROOT}/lib/Adapters/Storage/Mongo/MongoTransform.js`);
const BSON = require(`${PS_ROOT}/node_modules/bson`);
const { EJSON } = BSON;

function main() {
  let input = '';
  process.stdin.setEncoding('utf8');
  process.stdin.on('data', d => { input += d; });
  process.stdin.on('end', () => {
    const cases = JSON.parse(input);
    const failures = [];

    for (const c of cases) {
      let theirs;
      try {
        theirs = MongoTransform.parseObjectToMongoObjectForCreate(
          c.className,
          c.object,
          c.schema
        );
      } catch (e) {
        failures.push({ name: c.name, note: `upstream threw: ${e.message || e}` });
        continue;
      }

      // Round-trip through the real BSON serializer before comparing.
      //
      // This is not incidental. `parseObjectToMongoObjectForCreate` returns plain JS numbers and
      // the *driver* picks the wire type at serialization, so EJSON-stringifying the intermediate
      // measures the wrong thing: it renders an integer beyond int32 as $numberLong, while what
      // actually lands in MongoDB is a Double. Verified by writing through real parse-server and
      // reading the stored type back with `promoteValues: false`. Serializing here makes the
      // comparison about wire bytes, which is the only thing that matters for data fidelity.
      const onWire = BSON.deserialize(BSON.serialize(theirs), { promoteValues: false });
      const theirsEjson = EJSON.stringify(onWire, { relaxed: false });
      const ours = c.rustBson;

      // Compare as parsed objects so key order does not matter. Key order in a BSON document is
      // preserved on the wire, but upstream builds the document by iterating the input, so any
      // ordering difference here would be an artifact of the harness rather than a real one.
      const a = JSON.parse(theirsEjson);
      const b = JSON.parse(ours);
      if (JSON.stringify(sortKeys(a)) !== JSON.stringify(sortKeys(b))) {
        failures.push({
          name: c.name,
          node: JSON.stringify(sortKeys(a)),
          rust: JSON.stringify(sortKeys(b)),
        });
      }
    }

    if (failures.length) {
      console.error(`FAIL: ${failures.length} of ${cases.length} cases diverge\n`);
      for (const f of failures) {
        console.error(`  ${f.name}`);
        if (f.note) {
          console.error(`    ${f.note}`);
        } else {
          console.error(`    node: ${f.node}`);
          console.error(`    rust: ${f.rust}`);
        }
      }
      process.exit(1);
    }
    console.log(`OK: ${cases.length} transform cases match MongoTransform exactly`);
  });
}

function sortKeys(v) {
  if (Array.isArray(v)) { return v.map(sortKeys); }
  if (v && typeof v === 'object') {
    return Object.keys(v).sort().reduce((acc, k) => { acc[k] = sortKeys(v[k]); return acc; }, {});
  }
  return v;
}

main();
