// Package plugin provides shared go-plugin glue used by both the host and
// analyzer plugin processes.
//
// Both sides import this package so that the magic cookie, protocol version,
// and plugin name constant stay in one canonical place — drift between host and
// plugin handshake config is a compile-time impossibility rather than a runtime
// surprise.
//
// Plugin processes call Serve to start their gRPC server; the host uses
// NewGRPCPlugin plus the exported HandshakeConfig when constructing a
// go-plugin Client.
package plugin
