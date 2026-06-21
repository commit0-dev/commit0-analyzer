// Package vulnlib is a tiny synthetic library with a seeded "vulnerable" symbol.
// Tests treat VulnerableFunc as the advisory target.
package vulnlib

import "fmt"

// VulnerableFunc is the seeded vulnerable symbol used in all fixture tests.
func VulnerableFunc() string {
	return fmt.Sprintf("vuln called")
}

// SafeFunc is a symbol that is NOT flagged as vulnerable.
func SafeFunc() string {
	return "safe"
}

// Helper is called by VulnerableFunc in transitive-call fixtures.
func Helper() string {
	return VulnerableFunc()
}

// Doer is an interface whose implementation is VulnerableFunc-calling.
type Doer interface {
	Do() string
}

// VulnDoer implements Doer and calls VulnerableFunc.
type VulnDoer struct{}

// Do calls VulnerableFunc and satisfies the Doer interface.
func (v VulnDoer) Do() string {
	return VulnerableFunc()
}

// SafeDoer implements Doer without calling VulnerableFunc.
type SafeDoer struct{}

// Do returns a safe value and satisfies the Doer interface.
func (s SafeDoer) Do() string {
	return "safe"
}
