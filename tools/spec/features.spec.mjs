/*
 * Conformance runner for `spec/features.spec.js`, replayed against parse-rust.
 *
 * This is the seed of the conformance harness. It is not yet Jasmine driven by upstream's
 * `spec/helper.js`, which boots a server in-process. What it does instead is assert, over real
 * HTTP against a real parse-rust process, exactly what the upstream spec file asserts, so
 * "this spec file passes" is a measurement rather than an aspiration.
 *
 * The source is quoted inline per assertion so a reader can check the transcription without
 * opening the upstream checkout.
 *
 * Per-block categorization is required from the very first file, not added later: block 2 of
 * this file spies on the Node logger, which no HTTP-level harness can reproduce.
 *
 * Usage:  node tools/spec/features.spec.mjs http://127.0.0.1:27800/parse
 *
 * Point it at a real parse-server to check the harness itself. Every assertion here has been
 * verified to pass against parse-server at the pin, so a failure means parse-rust diverged,
 * not that the expectation was invented.
 *
 * **That property is a constraint on what may be added to this file.** An assertion that holds
 * only for parse-rust breaks it silently: the file keeps claiming to be differential while no
 * longer being runnable against upstream, and the claim is the only thing making a failure here
 * meaningful. Deliberate divergences are asserted in the Rust tests instead. The `/serverInfo`
 * capability values are the current example, in `crates/parse-rust-server/tests/server_info.rs`.
 */

const BASE = process.argv[2];
if (!BASE) {
  console.error('usage: node tools/spec/features.spec.mjs <server-url>');
  process.exit(2);
}

const APP_ID = 'test';
const MASTER_KEY = 'test';
const REST_KEY = 'rest';

// A floor, because a check that can pass by finding nothing will. A block that throws early, or
// one dropped in a refactor, lands below this and fails rather than reporting a green run.
const ASSERTION_FLOOR = 17;

let passed = 0;
const failures = [];

function check(name, cond, detail) {
  if (cond) {
    passed++;
  } else {
    failures.push(`${name}: ${detail}`);
  }
}

/* --------------------------------------------------------------------------
 * Block 1: "should return the serverInfo"
 *
 *   const response = await request({ url: '.../serverInfo', headers: {
 *     'X-Parse-Application-Id': 'test',
 *     'X-Parse-REST-API-Key': 'rest',
 *     'X-Parse-Master-Key': 'test',
 *   }});
 *   expect(data).toBeDefined();
 *   expect(data.features).toBeDefined();
 *   expect(data.parseServerVersion).toBeDefined();
 *
 * Category: surface-only. Portable as-is.
 * -------------------------------------------------------------------------- */
async function blockOne() {
  const res = await fetch(`${BASE}/serverInfo`, {
    headers: {
      'X-Parse-Application-Id': APP_ID,
      'X-Parse-REST-API-Key': REST_KEY,
      'X-Parse-Master-Key': MASTER_KEY,
    },
  });
  const data = await res.json().catch(() => undefined);

  check('block1 status', res.status === 200, `expected 200, got ${res.status}`);
  check('block1 data defined', data !== undefined, 'body was not JSON');
  check('block1 features defined', data?.features !== undefined, 'features missing');
  check(
    'block1 parseServerVersion defined',
    data?.parseServerVersion !== undefined,
    'parseServerVersion missing'
  );

  // Beyond what the spec asserts, but still true of both servers. The *shape* of the capability
  // block is wire contract: Parse Dashboard reads these keys, and a missing one would be
  // invisible to the spec's `toBeDefined()`.
  //
  // The *values* are deliberately not checked here. parse-rust reports what it implements rather
  // than upstream's hardcoded `true`, so an assertion on those booleans would fail against real
  // parse-server and break this file's contract. That check lives in
  // `crates/parse-rust-server/tests/server_info.rs`, where it belongs.
  for (const key of ['globalConfig', 'hooks', 'cloudCode', 'logs', 'push', 'schemas', 'settings']) {
    check(`features.${key} is present`, data?.features?.[key] !== undefined, 'key missing');
  }
  check(
    'features.schemas.exportClass is false',
    data?.features?.schemas?.exportClass === false,
    `got ${JSON.stringify(data?.features?.schemas?.exportClass)}`
  );
}

/* --------------------------------------------------------------------------
 * Block 2: "requires the master key to get features"
 *
 *   expect(error.status).toEqual(403);
 *   expect(error.data.error).toEqual('Permission denied');
 *   expect(loggerErrorSpy).toHaveBeenCalledWith('Sanitized error:', ...);
 *
 * Category: needs-internal-hooks, PARTIAL. The status and body are HTTP surface and are
 * asserted here. The logger spy reaches into the Node process's module graph and is not
 * reproducible over HTTP by any harness; it is recorded as out of scope for this row rather
 * than quietly dropped.
 * -------------------------------------------------------------------------- */
async function blockTwo() {
  const res = await fetch(`${BASE}/serverInfo`, {
    headers: {
      'X-Parse-Application-Id': APP_ID,
      'X-Parse-REST-API-Key': REST_KEY,
    },
  });
  const data = await res.json().catch(() => undefined);

  check('block2 status', res.status === 403, `expected 403, got ${res.status}`);
  check(
    'block2 error message',
    data?.error === 'Permission denied',
    `expected 'Permission denied', got ${JSON.stringify(data?.error)}`
  );
  // Not asserted by the spec, but load-bearing: this envelope carries no `code`, and SDKs
  // branch on its presence to tell a Parse error from an HTTP rejection.
  check(
    'block2 body has no code key',
    data !== undefined && !('code' in data),
    `unexpected code: ${JSON.stringify(data)}`
  );
}

/* --------------------------------------------------------------------------
 * Not from features.spec.js. The header layer's own rejection, which upstream answers with a
 * different body than the master-key gate. Two 403s that look alike and are not.
 * -------------------------------------------------------------------------- */
async function headerLayer() {
  const missingAppId = await fetch(`${BASE}/serverInfo`, {
    headers: { 'X-Parse-Master-Key': MASTER_KEY },
  });
  const body = await missingAppId.json().catch(() => undefined);
  check('no appId is 403', missingAppId.status === 403, `got ${missingAppId.status}`);
  check(
    'no appId says unauthorized, not Permission denied',
    body?.error === 'unauthorized',
    `got ${JSON.stringify(body?.error)}`
  );
}

async function main() {
  await blockOne();
  await blockTwo();
  await headerLayer();

  if (failures.length) {
    console.error(`FAIL  ${failures.length} assertion(s):`);
    for (const f of failures) {
      console.error(`  - ${f}`);
    }
    process.exit(1);
  }
  if (passed < ASSERTION_FLOOR) {
    console.error(`FAIL  features.spec.js ran ${passed} assertions, floor is ${ASSERTION_FLOOR}`);
    process.exit(1);
  }
  console.log(`OK  features.spec.js: ${passed} assertions pass against ${BASE}`);
}

main().catch(e => {
  console.error('harness error:', e.message);
  process.exit(2);
});
