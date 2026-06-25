export async function loadDynamic() {
  const name = getModuleName();
  const m = await import(name);
  return m;
}
