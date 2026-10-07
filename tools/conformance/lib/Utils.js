'use strict';
// `../lib/Utils` is upstream's pure helper module, with no server in it, so the vendored specs get
// the real one. `Utils.isDate` and the like assert on values the SDK returned.
const path = require('path');
module.exports = require(path.join(process.env.PS_ROOT, 'lib/Utils'));
