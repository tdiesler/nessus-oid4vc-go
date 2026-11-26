package common

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestNewCredentialIssuerMetadata(t *testing.T) {
	cfg := &AppConfig{
		CredentialConfigurations: []CredentialConfig{
			{Id: "natural_person_sd", Format: "dc+sd-jwt", Vct: "NaturalPersonCredential", Claims: []string{"email"}},
			{Id: "natural_person_jwt", Format: "jwt_vc_json", Vct: "NaturalPersonCredential", Claims: []string{"email"}},
		},
		Scopes: []ScopeConfig{
			{Name: "natural_person", CredentialConfigurationIds: []string{"natural_person_sd", "natural_person_jwt"}},
		},
	}

	metadata := NewCredentialIssuerMetadata("https://issuer.test", cfg)

	require.Equal(t, "https://issuer.test", metadata.CredentialIssuer)
	require.Equal(t, "https://issuer.test/credential", metadata.CredentialEndpoint)
	require.Equal(t, "https://issuer.test/nonce", metadata.NonceEndpoint)
	require.Equal(t, []string{"https://issuer.test"}, metadata.AuthorizationServers)
	require.Equal(t, map[string]CredentialConfigurationSupported{
		"natural_person_sd": {
			Format:                               "dc+sd-jwt",
			Scope:                                "natural_person",
			Vct:                                  "NaturalPersonCredential",
			CryptographicBindingMethodsSupported: []string{"jwk"},
			CredentialSigningAlgValuesSupported:  []string{"ES256"},
			ProofTypesSupported:                  map[string]ProofTypeSupported{"jwt": {ProofSigningAlgValuesSupported: []string{"ES256"}}},
			CredentialMetadata:                   &CredentialMetadataSupported{Claims: []ClaimMetadata{{Path: []string{"email"}}}},
		},
		"natural_person_jwt": {
			Format:                               "jwt_vc_json",
			Scope:                                "natural_person",
			CryptographicBindingMethodsSupported: []string{"jwk"},
			CredentialSigningAlgValuesSupported:  []string{"ES256"},
			ProofTypesSupported:                  map[string]ProofTypeSupported{"jwt": {ProofSigningAlgValuesSupported: []string{"ES256"}}},
			CredentialDefinition:                 &CredentialDefinition{Type: []string{"VerifiableCredential", "NaturalPersonCredential"}},
			CredentialMetadata:                   &CredentialMetadataSupported{Claims: []ClaimMetadata{{Path: []string{"credentialSubject", "email"}}}},
		},
	}, metadata.CredentialConfigurationsSupported)
}
