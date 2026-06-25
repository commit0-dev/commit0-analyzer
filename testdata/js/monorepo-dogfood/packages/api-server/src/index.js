// api-server entrypoint — imports and calls serialize-javascript (vulnerable version).
// serialize-javascript@2.1.4 is affected by GHSA-h9rv-jmmf-4pgx (XSS via crafted
// input in serialize()). The call below is reachable from this entrypoint,
// making this a PACKAGE_REACHABLE finding per the conservative-flow engine.
const serialize = require("serialize-javascript");

function handleRequest(data) {
  // Passes user-controlled data through the vulnerable serialize() function.
  return serialize(data, { isJSON: true });
}

module.exports = { handleRequest };
