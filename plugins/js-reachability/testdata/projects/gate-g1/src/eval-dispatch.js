// Non-import dynamic dispatch: eval() and computed member call.
// A reachable file containing these constructs must emit UNKNOWN frontiers
// so any package that could be loaded through them yields CONFIDENCE_UNKNOWN.

function runCode(code) {
  // eval with dynamic code → UNKNOWN frontier
  return eval(code);
}

function callMethod(obj, method) {
  // Computed member call obj[expr]() → UNKNOWN frontier
  return obj[method]();
}

module.exports = { runCode, callMethod };
