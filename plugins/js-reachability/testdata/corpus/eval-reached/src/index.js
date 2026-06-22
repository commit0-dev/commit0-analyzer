function runDynamic(code) {
  // eval creates an UNKNOWN frontier — the engine cannot follow inside eval.
  return eval(code);
}

module.exports = { runDynamic };
