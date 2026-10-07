/*
 * The oracle: parse-server built at the pin, booted out of process, for Gate F condition 5 and for
 * classifying blocks.
 *
 * **Out of process, and with `directAccess: false`**, so the vendored suite reaches it over a
 * socket exactly as it reaches parse-rust. The harness then cannot tell the two targets apart
 * except by the URL it was given, which is the point.
 *
 * `POST /_oracle/reset` is upstream's own `afterEach` cleanup (`spec/helper.js:284-290`):
 * `destroyAllDataPermanently(true)`, `SchemaCache.clear()` and `performInitialization`. It has to
 * run in this process, because the schema cache it clears lives here.
 *
 * Prints one line, `ORACLE {"url":..,"reset":..}`, once listening.
 */
import { createRequire } from 'node:module';

process.env.TESTING = '1';
const PS_ROOT = process.env.PS_ROOT;
const DB = process.env.CONFORMANCE_DB_URI;
const require = createRequire(`${PS_ROOT}/`);
const { ParseServer } = require(`${PS_ROOT}/lib/index.js`);
const TestUtils = require(`${PS_ROOT}/lib/TestUtils`);
const SchemaCache = require(`${PS_ROOT}/lib/Adapters/Cache/SchemaCache`).default;
const Config = require(`${PS_ROOT}/lib/Config`);
const { VolatileClassesSchemas } = require(`${PS_ROOT}/lib/Controllers/SchemaController`);

const server = await ParseServer.startApp({
  appId: 'test',
  masterKey: 'test',
  javascriptKey: 'test',
  clientKey: 'client',
  restAPIKey: 'rest',
  dotNetKey: 'windows',
  databaseURI: DB,
  mountPath: '/1',
  host: '127.0.0.1',
  port: 0,
  serverURL: 'http://127.0.0.1/1',
  allowClientClassCreation: true,
  directAccess: false,
  silent: true,
  // A reconfigure's options, as the spec asked for them, over the defaults above.
  ...JSON.parse(process.env.CONFORMANCE_OPTIONS || '{}'),
  databaseURI: DB,
  mountPath: '/1',
  port: 0,
});
const port = server.server.address().port;
server.expressApp.post('/_oracle/reset', async (_req, res) => {
  try {
    await TestUtils.destroyAllDataPermanently(true);
    SchemaCache.clear();
    await Config.get('test').database.adapter.performInitialization({ VolatileClassesSchemas });
    res.status(200).json({});
  } catch (e) {
    res.status(500).json({ error: String(e) });
  }
});
console.log(`ORACLE ${JSON.stringify({
  url: `http://127.0.0.1:${port}/1`,
  reset: `http://127.0.0.1:${port}/_oracle/reset`,
})}`);
