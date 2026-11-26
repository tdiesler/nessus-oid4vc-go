package oid4vci

import (
	"testing"

	"github.com/stretchr/testify/require"
	co "github.com/tdiesler/nessus-oid4vc-go/pkg/common"
)

// TestCredentialIssuerMetadata fetches the real /.well-known/openid-credential-issuer
// document over HTTP and checks it carries every field a wallet needs to
// drive the Credential Endpoint without hardcoding its URL shape:
// credential_endpoint/nonce_endpoint/authorization_servers built from the
// server's issuer identity (not its bind address), and each credential
// configuration's claims, signing/proof capabilities, and format-specific
// vct/credential_definition.
func TestCredentialIssuerMetadata(t *testing.T) {

	oauth, err := NewOAuthClient()
	require.NoError(t, err)

	metadata, err := oauth.FetchCredentialIssuerMetadata()
	require.NoError(t, err)

	require.Equal(t, testIssuer, metadata.CredentialIssuer)
	require.Equal(t, testIssuer+"/credential", metadata.CredentialEndpoint)
	require.Equal(t, testIssuer+"/nonce", metadata.NonceEndpoint)
	require.Equal(t, []string{testIssuer}, metadata.AuthorizationServers)

	claims := []string{"id", "email", "firstName", "familyName"}
	require.Equal(t, co.CredentialConfigurationSupported{
		Format:                               "dc+sd-jwt",
		Scope:                                "natural_person",
		Vct:                                  "NaturalPerson",
		CryptographicBindingMethodsSupported: []string{"jwk"},
		CredentialSigningAlgValuesSupported:  []string{"ES256"},
		ProofTypesSupported:                  map[string]co.ProofTypeSupported{"jwt": {ProofSigningAlgValuesSupported: []string{"ES256"}}},
		CredentialMetadata:                   &co.CredentialMetadataSupported{Claims: claimMetadata(claims, nil)},
	}, metadata.CredentialConfigurationsSupported["natural_person_sd"])

	require.Equal(t, co.CredentialConfigurationSupported{
		Format:                               "jwt_vc_json",
		Scope:                                "natural_person",
		CryptographicBindingMethodsSupported: []string{"jwk"},
		CredentialSigningAlgValuesSupported:  []string{"ES256"},
		ProofTypesSupported:                  map[string]co.ProofTypeSupported{"jwt": {ProofSigningAlgValuesSupported: []string{"ES256"}}},
		CredentialDefinition:                 &co.CredentialDefinition{Type: []string{"VerifiableCredential", "NaturalPerson"}},
		CredentialMetadata:                   &co.CredentialMetadataSupported{Claims: claimMetadata(claims, []string{"credentialSubject"})},
	}, metadata.CredentialConfigurationsSupported["natural_person_jwt"])
}

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

// Private ---------------------------------------------------------------------------------------------------------------

// claimMetadata builds the []co.ClaimMetadata expected for claims, each
// nested under prefix.
func claimMetadata(claims, prefix []string) []co.ClaimMetadata {
	out := make([]co.ClaimMetadata, len(claims))
	for i, name := range claims {
		out[i] = co.ClaimMetadata{Path: append(append([]string{}, prefix...), name)}
	}
	return out
}
