const serialize = require("serialize-javascript");

export function safeRun(data) {
  return serialize(data);
}
