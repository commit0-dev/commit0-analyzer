const { serialize } = require("serialize-javascript");

function callIt(data) {
  return serialize(data);
}

module.exports = { callIt };
