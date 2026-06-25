function loadPlugin(name) {
  // non-literal specifier → UNKNOWN frontier
  return require(name);
}

module.exports = { loadPlugin };
