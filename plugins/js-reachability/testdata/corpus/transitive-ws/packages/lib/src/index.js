import serialize from "serialize-javascript";

export function processData(data) {
  return serialize(data);
}
