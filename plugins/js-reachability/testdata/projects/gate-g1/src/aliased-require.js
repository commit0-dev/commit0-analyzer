// Aliased require: const req = require; req(name)
// The call-graph builder sees require bound to a variable and then invoked
// with a non-literal — this must emit an UNKNOWN frontier.

const req = require;

function loadDep(name) {
  // Aliased require call with dynamic specifier → UNKNOWN frontier
  return req(name);
}

module.exports = { loadDep };
