package contract_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ducthinh993/anst-analyzer/pkg/contract"
)

func TestProtocolVersion_Present(t *testing.T) {
	// ProtocolVersion must be a non-empty string constant.
	require.NotEmpty(t, contract.ProtocolVersion, "ProtocolVersion must be set")
}

func TestProtocolVersion_MajorAndMinor(t *testing.T) {
	// Major and Minor must be separately accessible.
	assert.GreaterOrEqual(t, contract.ProtocolMajor, 0, "ProtocolMajor must be >= 0")
	assert.GreaterOrEqual(t, contract.ProtocolMinor, 0, "ProtocolMinor must be >= 0")
}

func TestCompatible_SameVersion(t *testing.T) {
	// Equal major and minor must be compatible.
	assert.True(t, contract.Compatible(contract.ProtocolMajor, contract.ProtocolMinor),
		"plugin with same major.minor must be compatible")
}

func TestCompatible_RejectsMajorMismatch(t *testing.T) {
	// A different major version is always incompatible, regardless of minor.
	wrongMajor := contract.ProtocolMajor + 1
	assert.False(t, contract.Compatible(wrongMajor, contract.ProtocolMinor),
		"plugin with higher major must be rejected")

	if contract.ProtocolMajor > 0 {
		assert.False(t, contract.Compatible(contract.ProtocolMajor-1, contract.ProtocolMinor),
			"plugin with lower major must be rejected")
	}
}

func TestCompatible_AcceptsLowerOrEqualMinor(t *testing.T) {
	// Host minor >= plugin minor: plugin asks for at most what the host supports.
	// Plugin minor == host minor: compatible.
	assert.True(t, contract.Compatible(contract.ProtocolMajor, contract.ProtocolMinor),
		"equal minor must be compatible")

	// Plugin minor < host minor: plugin needs fewer features, host can serve it.
	if contract.ProtocolMinor > 0 {
		assert.True(t, contract.Compatible(contract.ProtocolMajor, contract.ProtocolMinor-1),
			"plugin with lower minor must be compatible")
	}
}

func TestCompatible_RejectsHigherMinor(t *testing.T) {
	// Plugin minor > host minor: plugin requires features the host doesn't have.
	higherMinor := contract.ProtocolMinor + 1
	assert.False(t, contract.Compatible(contract.ProtocolMajor, higherMinor),
		"plugin with higher minor than host must be rejected")
}
