// Computed-member dispatch: the ONLY path to serialize-javascript is through
// handlers[name](data) where the method key is a runtime variable.
//
// The engine detects obj[expr]() as a dynamic-dispatch frontier and cannot
// statically determine which handler is called, so the verdict is UNKNOWN.
// serialize-javascript is NOT statically imported here.

function dispatch(handlers, name, data) {
  // Computed member call obj[key]() — engine emits a dynamic-dispatch
  // UNKNOWN frontier. Which handler is invoked is not known statically.
  return handlers[name](data);
}

module.exports = { dispatch };
