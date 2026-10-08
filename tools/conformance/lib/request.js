'use strict';
// `../lib/request` for the vendored specs: upstream's own HTTP client, with the conformance tag
// added to every request, so a block using it directly is attributed like one using the SDK.
const path = require('path');
const upstream = require(path.join(process.env.PS_ROOT, 'lib/request'));
const real = upstream.default || upstream;

function request(options) {
  global.__conformanceCount?.();
  const headers = { ...(options.headers || {}), 'X-Parse-Conformance-Block': global.__conformanceTag() };
  return real({ ...options, headers });
}
module.exports = request;
module.exports.default = request;
module.exports.encodeBody = real.encodeBody;
module.exports.HTTPResponse = real.HTTPResponse;
