'use strict';
// Stubs for the modules a spec uses to drive parse-server **in process**: `ParseServer`,
// `ParseServerRESTController`, `Deprecator`. They load, so a file that imports them at the top
// still runs its other blocks; any use throws, so the block that needs a server in this process
// fails loudly instead of reaching one.
function inProcess(name) {
  return new Proxy(function () {}, {
    get(_, prop) {
      if (prop === '__esModule' || prop === 'then' || typeof prop === 'symbol') { return undefined; }
      throw new Error(`conformance: ${name}.${String(prop)} drives parse-server in process, which this harness does not run`);
    },
    apply() {
      throw new Error(`conformance: ${name}() drives parse-server in process, which this harness does not run`);
    },
  });
}
module.exports = inProcess;
