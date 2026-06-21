package plugin

import (
	"context"
	"fmt"
	"net/rpc"

	goplugin "github.com/hashicorp/go-plugin"
	"google.golang.org/grpc"

	"github.com/ducthinh993/anst-analyzer/pkg/contract"
	anstv1 "github.com/ducthinh993/anst-analyzer/pkg/contract/anstv1"
)

const (
	// PluginName is the canonical key used in go-plugin's PluginSet.
	// Both host and plugins must agree on this string.
	PluginName = "analyzer"

	// MagicCookieKey and MagicCookieValue form the first layer of the plugin
	// trust boundary: a plugin launched without these env vars set by the host
	// will print a human-readable error and exit instead of trying to serve.
	// This is not a cryptographic secret — it is a UX guard against accidental
	// execution. Binary hash pinning (SecureConfig) in internal/host is the
	// actual integrity mechanism.
	MagicCookieKey   = "ANST_PLUGIN_MAGIC_COOKIE"
	MagicCookieValue = "anst-analyzer-v0-plugin"
)

// HandshakeConfig is the shared go-plugin handshake used by both host and
// plugin binaries. The ProtocolVersion is derived from contract.ProtocolMajor
// (offset +1 so that major=0 yields a non-zero go-plugin protocol number)
// so that a breaking-change version bump in the contract automatically changes
// the go-plugin negotiation value.
var HandshakeConfig = goplugin.HandshakeConfig{
	ProtocolVersion:  uint(contract.ProtocolMajor + 1), // 0→1, 1→2, …
	MagicCookieKey:   MagicCookieKey,
	MagicCookieValue: MagicCookieValue,
}

// AnalyzerGRPCPlugin is the go-plugin plugin type that carries the
// anstv1.Analyzer gRPC service. It implements both goplugin.Plugin
// (net/rpc path, which we reject) and goplugin.GRPCPlugin.
//
// Host side: set Impl to nil; GRPCClient returns an anstv1.AnalyzerClient.
// Plugin side: set Impl to the concrete AnalyzerServer; GRPCServer registers it.
type AnalyzerGRPCPlugin struct {
	// Impl is the server-side implementation. It must be non-nil on the plugin
	// (server) process and is ignored on the host (client) process.
	Impl anstv1.AnalyzerServer
}

// GRPCServer registers the AnalyzerServer implementation with the go-plugin
// managed gRPC server. Called by go-plugin on the plugin process side.
func (p *AnalyzerGRPCPlugin) GRPCServer(_ *goplugin.GRPCBroker, s *grpc.Server) error {
	if p.Impl == nil {
		return fmt.Errorf("plugin.AnalyzerGRPCPlugin: Impl must be set on the server side")
	}
	anstv1.RegisterAnalyzerServer(s, p.Impl)
	return nil
}

// GRPCClient returns an anstv1.AnalyzerClient connected over the go-plugin
// managed gRPC connection. Called by go-plugin on the host (client) side.
// The returned value is an anstv1.AnalyzerClient; the caller must type-assert.
func (p *AnalyzerGRPCPlugin) GRPCClient(
	_ context.Context,
	_ *goplugin.GRPCBroker,
	cc *grpc.ClientConn,
) (interface{}, error) {
	return anstv1.NewAnalyzerClient(cc), nil
}

// Server implements goplugin.Plugin for the net/rpc path, which is not
// supported. It always returns an error.
func (p *AnalyzerGRPCPlugin) Server(_ *goplugin.MuxBroker) (interface{}, error) {
	return nil, fmt.Errorf("plugin.AnalyzerGRPCPlugin: net/rpc is not supported; use gRPC")
}

// Client implements goplugin.Plugin for the net/rpc path, which is not
// supported. It always returns an error.
func (p *AnalyzerGRPCPlugin) Client(_ *goplugin.MuxBroker, _ *rpc.Client) (interface{}, error) {
	return nil, fmt.Errorf("plugin.AnalyzerGRPCPlugin: net/rpc is not supported; use gRPC")
}

// PluginMap returns a go-plugin PluginSet with impl registered under PluginName.
// Pass impl=nil on the host (client) side.
func PluginMap(impl anstv1.AnalyzerServer) goplugin.PluginSet {
	return goplugin.PluginSet{
		PluginName: &AnalyzerGRPCPlugin{Impl: impl},
	}
}

// Serve starts the plugin gRPC server. Plugin binaries call this from their
// main(). It blocks until the host closes the connection, then exits.
//
// Usage in a plugin main():
//
//	func main() { plugin.Serve(&myAnalyzer{}) }
func Serve(impl anstv1.AnalyzerServer) {
	goplugin.Serve(&goplugin.ServeConfig{
		HandshakeConfig: HandshakeConfig,
		Plugins:         PluginMap(impl),
		GRPCServer:      goplugin.DefaultGRPCServer,
	})
}
