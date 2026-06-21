package main

import (
	"os"

	"github.com/ducthinh993/anst-analyzer/internal/cli"
	"github.com/ducthinh993/anst-analyzer/internal/policy"
)

// main is the anst-analyzer entry point.
//
// It wraps the CLI run in policy.RunWithRecovery so that any unexpected panic
// inside the CLI produces exit code 3 (operational error / fail-closed) rather
// than Go's default exit code 2, which would collide with govulncheck's exit
// semantics and incorrectly signal a clean pass to CI tooling (Red Team #8).
func main() {
	os.Exit(policy.RunWithRecovery(func() int {
		return cli.Run(os.Args[1:])
	}))
}
