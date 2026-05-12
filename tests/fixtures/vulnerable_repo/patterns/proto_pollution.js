// Prototype pollution fixture for Suzaku Compass tests.

const _ = require('lodash');

function pollute(target, untrusted) {
  _.merge(target, untrusted);
  _.defaultsDeep(target, untrusted);
}

function rawAccess(obj) {
  obj["__proto__"] = { polluted: true };
}
