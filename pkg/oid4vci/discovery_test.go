package oid4vci

import (
	"testing"

	"github.com/stretchr/testify/require"
	co "github.com/tdiesler/nessus-oid4vc-go/pkg/common"
)

func TestNewMetadata(t *testing.T) {
	cfg := &co.AppConfig{
		Scopes: []co.ScopeConfig{
			{Name: "natural_person", CredentialConfigurationIds: []string{"natural_person_sd"}},
		},
	}

	metadata := NewMetadata("https://issuer.test", cfg)

	require.Equal(t, "https://issuer.test", metadata.Issuer)
	require.Equal(t, []string{"openid", "natural_person"}, metadata.ScopesSupported)
}
