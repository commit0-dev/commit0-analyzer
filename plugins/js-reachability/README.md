# js-reachability plugin

JS/TS SCA reachability analyzer plugin for `commit0-analyzer`. Implements the
`commit0.v1.Analyzer` gRPC service over the `hashicorp/go-plugin` v1.8.0 subprocess
transport.

## Distribution layout

The plugin ships as two files:

```
dist/
  commit0-js-reachability              # compiled Bun binary (main executable)
  oxc-binding/
    parser.<platform>-<arch>.node   # oxc native addon sidecar
```

A single binary is not possible because the OS cannot `dlopen` a native `.node`
addon from memory. The host (CLI) pins the SHA-256 of **both** files; launch
with a tampered sidecar or binary is rejected.

## Build

Requires [Bun](https://bun.sh) on PATH (not yet installed at skeleton time —
the build script is ready; install Bun first):

```sh
make build-js-plugin
```

Which runs:
```sh
cd plugins/js-reachability
bun install
bun build src/main.ts --compile --outfile dist/commit0-js-reachability
# then places the oxc sidecar at dist/oxc-binding/parser.<platform>.node
```

> **Note:** `bun build --compile` was not run during Phase 1 because Bun is
> not yet installed in the build environment. The Makefile target and package
> script are correct and will work once Bun is on PATH.

## Development

```sh
cd plugins/js-reachability
npm install          # installs deps including ts-proto for stub generation
npm test             # runs vitest
npm run typecheck    # tsc --noEmit
```

### Regenerate TS stubs

From the repo root:

```sh
buf generate --template buf.gen.js.yaml
```

Stubs are committed to `src/gen/` (parity with Go's committed
`pkg/contract/commit0v1/` stubs). Regenerate whenever `proto/commit0/v1/plugin.proto`
changes.

## Transport details

### go-plugin v1.8.0 handshake

Magic-cookie guard (checked before the server starts):

| Env var                  | Required value            |
|--------------------------|---------------------------|
| `ANST_PLUGIN_MAGIC_COOKIE` | `commit0-analyzer-v0-plugin` |

If the env var is absent or wrong the binary prints a human-readable error to
stderr and exits 1. This is a UX guard against accidental direct execution, not
a cryptographic secret — binary hash-pinning in the host is the real integrity
mechanism.

Handshake stdout line (one line, then silence on stdout forever after):

```
1|1|tcp|127.0.0.1:<port>|grpc\n
```

Fields: `CoreProtocol | AppProto | network | address | protocol-type`

- `CoreProtocol = 1` — literal; always 1 in the 5-field form.
- `AppProto = ProtocolMajor + 1 = 0 + 1 = 1` — must match host or version gate
  fails before `Metadata` is called.
- `network = tcp` — cross-platform; avoids unix-socket portability issues.
- `protocol-type = grpc` — literal token; host `AllowedProtocols` is gRPC-only.

The 5-field form is accepted by go-plugin v1.8.0 because fields 6+
(`serverCert`, `grpcMux`) are optional — this is tolerance, not the canonical
7-field form. AutoMTLS is **OFF**: the host does not send `PLUGIN_CLIENT_CERT`,
so insecure credentials are correct.

### Four required gRPC services

| Service                  | Why required |
|--------------------------|--------------|
| `grpc.health.v1.Health`  | **Mandatory.** go-plugin `Ping()` calls `Health/Check` with `service="plugin"`; must return `SERVING` or the connection fails. |
| `commit0.v1.Analyzer`       | The actual plugin contract (`Metadata` + `Analyze`). |
| `plugin.GRPCController`  | `Shutdown()`: without it `Kill()` waits the 2-second grace period before SIGKILL. |
| `plugin.GRPCStdio`       | `StreamStdio` no-op: without it go-plugin logs an `Unimplemented` warning. |

### Lifecycle

1. Binary validates magic cookie.
2. gRPC server starts on `tcp 127.0.0.1:0` (ephemeral port, insecure credentials).
3. Handshake line written to stdout; all further stdout is gRPC framing only.
4. Server serves until stdin closes (host signals shutdown by closing stdin).

### Sidecar shim

When running as a compiled Bun binary, `Module._resolveFilename` is patched to
redirect `require('oxc-binding/parser.<platform>.node')` to
`dirname(process.execPath)/oxc-binding/<filename>`. This is a no-op during
development (normal `node_modules` resolution applies). See `src/sidecar.ts`.

### oxc sidecar filename per platform

| Platform      | Sidecar filename                       |
|---------------|----------------------------------------|
| macOS arm64   | `parser.darwin-arm64.node`             |
| macOS x64     | `parser.darwin-x64.node`              |
| Linux x64     | `parser.linux-x64-gnu.node`           |
| Linux arm64   | `parser.linux-arm64-gnu.node`         |
| Windows x64   | `parser.win32-x64-msvc.node`          |

CI must build and pin a per-target sidecar for each release platform.

The oxc package to fetch for the sidecar is `@oxc-parser/binding-<platform>`
(e.g. `@oxc-parser/binding-darwin-arm64`). Pin the exact version that matches
`oxc-parser` in `package.json` once oxc parsing is added in Phase 3.
