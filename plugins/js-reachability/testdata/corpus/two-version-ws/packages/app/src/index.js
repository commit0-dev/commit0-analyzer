const serialize = require("serialize-javascript");

function run(data) {
  return serialize(data);
}

module.exports = { run };
