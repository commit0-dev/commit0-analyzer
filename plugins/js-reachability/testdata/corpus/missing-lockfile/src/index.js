const serialize = require("serialize-javascript");

export function run(data) {
  return serialize(data);
}
