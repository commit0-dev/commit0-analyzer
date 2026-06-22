import path from "node:path";
import type { ProjectModel, Workspace, ResolvedPackage } from "./project/model.js";
import { buildProjectModel } from "./project/build-project-model.js";

/**
 * Serialize a ProjectModel to deterministic JSON.
 *
 * Maps are serialized as sorted arrays of [key, value] pairs so the output
 * is byte-identical across runs regardless of Map insertion order.
 * No wall-clock timestamps are included.
 */
export function serializeProjectModel(model: ProjectModel): string {
  const obj = {
    root: model.root,
    manager: model.manager,
    workspaces: model.workspaces.map(serializeWorkspace),
    incomplete: model.incomplete.map((e) => ({ scope: e.scope, reason: e.reason })),
  };
  return JSON.stringify(obj, null, 2);
}

function serializeWorkspace(ws: Workspace): object {
  // Convert deps Map to sorted array of entries for determinism
  const depsEntries: Array<[string, ReturnType<typeof serializeResolvedPkg>]> = [];
  for (const key of [...ws.deps.keys()].sort()) {
    const pkg = ws.deps.get(key)!;
    depsEntries.push([key, serializeResolvedPkg(pkg)]);
  }

  return {
    name: ws.name,
    dir: ws.dir,
    manifest: {
      name: ws.manifest.name,
      version: ws.manifest.version,
      dependencies: sortedObject(ws.manifest.dependencies),
      devDependencies: sortedObject(ws.manifest.devDependencies),
    },
    deps: Object.fromEntries(depsEntries),
    localDeps: [...ws.localDeps].sort(),
  };
}

function serializeResolvedPkg(pkg: ResolvedPackage): object {
  return { name: pkg.name, version: pkg.version, dir: pkg.dir };
}

function sortedObject(
  obj: Record<string, string> | undefined
): Record<string, string> | undefined {
  if (!obj) return undefined;
  const sorted: Record<string, string> = {};
  for (const k of Object.keys(obj).sort()) {
    sorted[k] = obj[k];
  }
  return sorted;
}

/** Entry point for the --project-model <dir> CLI mode. */
export async function run(): Promise<void> {
  const dirArg = process.argv[3];
  if (!dirArg) {
    process.stderr.write("Usage: --project-model <directory>\n");
    process.exit(1);
  }

  const dir = path.resolve(dirArg);
  const model = await buildProjectModel(dir);
  process.stdout.write(serializeProjectModel(model) + "\n");
}
