'use strict';
// `../lib/rest` for the vendored specs: a stub that throws on any use. A spec reaching it needs
// parse-server's internals, which this harness does not provide, and must report `not-run`
// loudly rather than being quietly satisfied by an in-process server (Gate F).
module.exports = new Proxy({}, {
  get(_, prop) {
    if (prop === '__esModule') { return false; }
    throw new Error('conformance: ../lib/rest.' + String(prop) + ' is not available in this harness');
  },
});
