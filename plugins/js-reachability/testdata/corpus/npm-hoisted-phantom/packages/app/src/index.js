const serialize = require("serialize-javascript");
const phantomDep = require("phantom-vuln-dep");

function run(data) {
  return serialize(data);
}

function runPhantom(data) {
  return phantomDep.process(data);
}

module.exports = { run, runPhantom };
