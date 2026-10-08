'use strict';
// `../lib/Config` for the vendored specs. Everything throws except the one shim 0.3.0 permits:
// `Config.get(appId).database.loadSchema()`, whose `addClassIfNotExists` and `updateClass` become
// `POST` and `PUT /schemas/:className` with the master key (Gate G). Those two are
// setup calls in the specs that use them, declaring a class and its CLP before asserting over
// HTTP, and the schema API is the same operation upstream's controller performs.
//
// `schemaCache.clear()` is a no-op: parse-rust loads the schema on every request and has no cache
// to clear, and the oracle's cache is updated by its own schema route.
//
// Any other property throws, so a spec reaching further into the controller reports `not-run`
// loudly rather than being quietly satisfied.

function fail(prop) {
  throw new Error(`conformance: ../lib/Config ${prop} is not available in this harness`);
}

async function schemaCall(method, className, body) {
  const response = await fetch(`${global.CONFORMANCE_SERVER_URL}/schemas/${className}`, {
    method,
    headers: {
      'X-Parse-Application-Id': 'test',
      'X-Parse-Master-Key': 'test',
      'Content-Type': 'application/json',
      'X-Parse-Conformance-Block': global.__conformanceTag(),
    },
    body: JSON.stringify(body),
  });
  global.__conformanceCount?.();
  const json = await response.json().catch(() => ({}));
  if (!response.ok) {
    throw new global.Parse.Error(json.code, json.error);
  }
  return json;
}

const schemaController = {
  addClassIfNotExists(className, fields = {}, classLevelPermissions, indexes) {
    return schemaCall('POST', className, {
      className, fields, classLevelPermissions, ...(indexes ? { indexes } : {}),
    });
  },
  updateClass(className, fields = {}, classLevelPermissions, indexes) {
    return schemaCall('PUT', className, {
      className, fields, classLevelPermissions, ...(indexes ? { indexes } : {}),
    });
  },
};

const guard = (target, label) => new Proxy(target, {
  get(t, prop) {
    if (prop in t || typeof prop === 'symbol' || prop === 'then') { return t[prop]; }
    return fail(`${label}.${String(prop)}`);
  },
});

function get() {
  return guard({
    schemaCache: { clear() {} },
    database: guard({
      loadSchema: async () => guard(schemaController, 'schema'),
    }, 'database'),
  }, 'Config.get()');
}

module.exports = guard({ get, default: undefined }, 'Config');
module.exports.default = module.exports;
