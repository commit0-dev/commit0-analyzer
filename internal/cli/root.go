package cli

import (
	"github.com/spf13/cobra"
)

// NewRootCmd returns the top-level cobra command for commit0-analyzer.
// All sub-commands are registered here. Global flags (e.g. log level) are
// added to the persistent flag set so every sub-command inherits them.
func NewRootCmd() *cobra.Command {
	root := &cobra.Command{
		Use:   "commit0-analyzer",
		Short: "Reachability-first OSS security analyzer for Go modules",
		Long: `commit0-analyzer is a CI-native, reachability-first software composition
analysis tool. It resolves dependency vulnerabilities and determines whether the
vulnerable symbol is actually reachable from your entry points, emitting
SARIF/JSON/table output and gating CI on a policy-as-code threshold.

Exit codes:
  0  All findings within policy thresholds; scan complete.
  1  One or more findings exceeded the configured threshold.
  3  Operational error: incomplete scan, plugin crash, or build failure.`,
		// Disable the default completion command to keep the CLI surface minimal.
		CompletionOptions: cobra.CompletionOptions{DisableDefaultCmd: true},
		// SilenceUsage prevents cobra from printing the usage block on every error,
		// which is noisy in CI. Callers print usage explicitly where helpful.
		SilenceUsage: true,
	}

	root.AddCommand(newScanCmd())
	return root
}

// Run executes the root command and returns the process exit code.
// It is called from cmd/commit0-analyzer/main.go wrapped in policy.RunWithRecovery.
func Run(args []string) int {
	root := NewRootCmd()
	root.SetArgs(args)
	if err := root.Execute(); err != nil {
		// cobra already prints the error; propagate exit code 3 (operational error).
		return 3
	}
	// The scan sub-command manages its own exit code via os.Exit or the returned
	// integer; if cobra returns nil the root command itself passed cleanly.
	return 0
}
