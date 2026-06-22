import serialize from "serialize-javascript";

export function run(data: unknown): string {
  return serialize(data);
}
