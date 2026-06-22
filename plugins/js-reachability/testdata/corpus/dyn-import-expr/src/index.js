export async function loadModule(name) {
  const m = await import(name);
  return m;
}
