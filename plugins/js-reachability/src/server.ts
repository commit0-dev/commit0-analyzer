/**
 * Serve mode: complete the go-plugin handshake and serve gRPC until shutdown.
 */

import * as grpc from "@grpc/grpc-js";
import { checkMagicCookie, startAndHandshake, serveUntilDone } from "./handshake.js";
import { registerServices } from "./serve.js";

export async function run(): Promise<void> {
  checkMagicCookie();

  const server = new grpc.Server();
  registerServices(server);

  await startAndHandshake(server);
  await serveUntilDone(server);
}
