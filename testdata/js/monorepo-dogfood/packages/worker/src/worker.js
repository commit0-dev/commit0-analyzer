// worker entrypoint — does NOT import serialize-javascript.
// serialize-javascript is a workspace-level dep installed via hoisting, but
// this workspace never imports or calls it. The engine must emit NOT_REACHABLE
// for serialize-javascript in this workspace (installed, not reachable here).

function processTask(task) {
  return { status: "processed", id: task.id };
}

module.exports = { processTask };
