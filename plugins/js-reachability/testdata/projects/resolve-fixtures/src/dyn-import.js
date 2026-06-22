async function load() {
  const m = await import("./lazy");
  return m;
}
