package jwtvc

import (
	"encoding/json"
	"testing"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jose-util/generator"
	"github.com/stretchr/testify/require"
)

// TestBuilderBuildIsVerifiableAndBindsHolder builds a credential with one
// credentialSubject claim and holder binding, then checks every piece a
// verifier would rely on: the typ header, the signature, the VC Data
// Model's @context/type/credentialSubject shape, and the "cnf" claim
// carrying only the holder's public key.
func TestBuilderBuildIsVerifiableAndBindsHolder(t *testing.T) {

	issuerPub, issuerPriv, err := generator.NewSigningKey(jose.ES256, 0)
	require.NoError(t, err)
	holderKey := newTestHolderKey(t)

	b, err := NewBuilder("NaturalPerson", jose.SigningKey{Algorithm: jose.ES256, Key: issuerPriv})
	require.NoError(t, err)
	b.WithIssuer("https://issuer.example").
		WithSubject("alice").
		WithHolderBinding(holderKey).
		WithClaim("email", "alice@example.com")

	jwtVc, err := b.Build()
	require.NoError(t, err)

	sig, err := jose.ParseSigned(jwtVc, []jose.SignatureAlgorithm{jose.ES256})
	require.NoError(t, err)
	require.Equal(t, "JWT", sig.Signatures[0].Header.ExtraHeaders[jose.HeaderType])

	payload, err := sig.Verify(issuerPub)
	require.NoError(t, err)

	var claims map[string]any
	require.NoError(t, json.Unmarshal(payload, &claims))
	require.Equal(t, "https://issuer.example", claims["iss"])
	require.Equal(t, "alice", claims["sub"])
	require.NotNil(t, claims["nbf"])

	cnf, ok := claims["cnf"].(map[string]any)
	require.True(t, ok)
	jwk, ok := cnf["jwk"].(map[string]any)
	require.True(t, ok)
	require.NotContains(t, jwk, "d", "cnf.jwk must carry the holder's public key only")

	vc, ok := claims["vc"].(map[string]any)
	require.True(t, ok)
	require.Equal(t, []any{vcContext}, vc["@context"])
	require.Equal(t, []any{"VerifiableCredential", "NaturalPerson"}, vc["type"])
	require.NotContains(t, vc, "issuer", "issuer is carried by \"iss\" only, not duplicated in vc")
	require.NotContains(t, vc, "issuanceDate", "issuanceDate is carried by \"nbf\" only, not duplicated in vc")

	credentialSubject, ok := vc["credentialSubject"].(map[string]any)
	require.True(t, ok)
	require.Equal(t, "alice@example.com", credentialSubject["email"])
}

// TestNewBuilderRequiresVct checks that NewBuilder rejects an empty vct
// rather than building a credential with no verifiable credential type.
func TestNewBuilderRequiresVct(t *testing.T) {
	_, priv, err := generator.NewSigningKey(jose.ES256, 0)
	require.NoError(t, err)

	_, err = NewBuilder("", jose.SigningKey{Algorithm: jose.ES256, Key: priv})
	require.Error(t, err)
}

// Private ---------------------------------------------------------------------------------------------------------------

// newTestHolderKey generates a throwaway ES256 holder key for binding tests.
func newTestHolderKey(t *testing.T) jose.JSONWebKey {
	t.Helper()
	_, priv, err := generator.NewSigningKey(jose.ES256, 0)
	require.NoError(t, err)
	return jose.JSONWebKey{Key: priv, KeyID: "holder#1", Algorithm: string(jose.ES256), Use: "sig"}
}
