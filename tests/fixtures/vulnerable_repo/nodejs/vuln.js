// Intentionally vulnerable Node.js fixture for Suzaku Compass tests.
// DO NOT use this code. It exists only as scanner bait.

const _ = require('lodash');
const vm = require('vm');
const child_process = require('child_process');

function unsafeEval(code) {
  return eval(code);
}

function unsafeFunction(code) {
  return new Function(code)();
}

function unsafeVm(code) {
  return vm.runInNewContext(code);
}

function unsafeMerge(target, untrusted) {
  return _.merge(target, untrusted);
}

function unsafeMergeWith(target, untrusted) {
  return _.mergeWith(target, untrusted);
}

function unsafeExec(userInput) {
  child_process.exec('ls ' + userInput);
}

function dynamicRequire(name) {
  return require(name);
}

function unsafeAssign(target, untrusted) {
  Object.assign(target, untrusted);
}
