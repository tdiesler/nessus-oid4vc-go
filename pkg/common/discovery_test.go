package common

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestNewCredentialIssuerMetadata(t *testing.T) {
	cfg := &AppConfig{
		CredentialConfigurations: []CredentialConfig{
			{Id: "natural_person_sd", Format: "dc+sd-jwt", Vct: "NaturalPersonCredential"},
			{Id: "natural_person_jwt", Format: "jwt_vc_json", Vct: "NaturalPersonCredential"},
		},
		Scopes: []ScopeConfig{
			{Name: "natural_person", CredentialConfigurationIds: []string{"natural_person_sd", "natural_person_jwt"}},
		},
	}

	metadata := NewCredentialIssuerMetadata("https://issuer.test", cfg)

	require.Equal(t, "https://issuer.test", metadata.CredentialIssuer)
	require.Equal(t, map[string]CredentialConfigurationSupported{
		"natural_person_sd":  {Format: "dc+sd-jwt", Scope: "natural_person", Vct: "NaturalPersonCredential"},
		"natural_person_jwt": {Format: "jwt_vc_json", Scope: "natural_person", Vct: "NaturalPersonCredential"},
	}, metadata.CredentialConfigurationsSupported)
}
