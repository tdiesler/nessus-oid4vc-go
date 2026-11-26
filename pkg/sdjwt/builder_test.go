package sdjwt

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jose-util/generator"
	"github.com/stretchr/testify/require"
)

// TestBuilderBuildIsVerifiableAndBindsHolder builds a credential with one
// always-visible claim, one disclosable claim, and holder binding, then
// checks every piece a verifier would rely on: the typ header, the
// signature, the "_sd" digest matching the appended disclosure, and the
// "cnf" claim carrying only the holder's public key.
func TestBuilderBuildIsVerifiableAndBindsHolder(t *testing.T) {

	issuerPub, issuerPriv, err := generator.NewSigningKey(jose.ES256, 0)
	require.NoError(t, err)
	holderKey := newTestHolderKey(t)

	b, err := NewBuilder("NaturalPerson", jose.SigningKey{Algorithm: jose.ES256, Key: issuerPriv})
	require.NoError(t, err)
	b.WithIssuer("https://issuer.example").
		WithSubject("alice").
		WithExpiry(time.Now().Add(time.Hour)).
		WithHolderBinding(holderKey).
		WithClaim("role", "admin").
		WithDisclosableClaim("email", "alice@example.com")

	sdJwt, err := b.Build()
	require.NoError(t, err)

	parts := strings.Split(sdJwt, "~")
	require.Len(t, parts, 3, "signed JWT, one disclosure, trailing empty segment")
	require.Empty(t, parts[2])

	sig, err := jose.ParseSigned(parts[0], []jose.SignatureAlgorithm{jose.ES256})
	require.NoError(t, err)
	require.Equal(t, sdJwtVcType, sig.Signatures[0].Header.ExtraHeaders[jose.HeaderType])

	payload, err := sig.Verify(issuerPub)
	require.NoError(t, err)

	var claims map[string]any
	require.NoError(t, json.Unmarshal(payload, &claims))
	require.Equal(t, "NaturalPerson", claims["vct"])
	require.Equal(t, "https://issuer.example", claims["iss"])
	require.Equal(t, "alice", claims["sub"])
	require.Equal(t, "admin", claims["role"])
	require.Equal(t, sdAlgSha256, claims["_sd_alg"])

	cnf, ok := claims["cnf"].(map[string]any)
	require.True(t, ok)
	jwk, ok := cnf["jwk"].(map[string]any)
	require.True(t, ok)
	require.NotContains(t, jwk, "d", "cnf.jwk must carry the holder's public key only")

	name, value, digest := decodeDisclosure(t, parts[1])
	require.Equal(t, "email", name)
	require.Equal(t, "alice@example.com", value)
	require.Contains(t, claims["_sd"], digest)
}

// TestBuilderBuildOmitsSdClaimsWhenNoDisclosableClaims checks that a
// credential with only always-visible claims carries neither "_sd" nor
// "_sd_alg", and serializes with no disclosure segments.
func TestBuilderBuildOmitsSdClaimsWhenNoDisclosableClaims(t *testing.T) {

	_, priv, err := generator.NewSigningKey(jose.ES256, 0)
	require.NoError(t, err)

	b, err := NewBuilder("NaturalPerson", jose.SigningKey{Algorithm: jose.ES256, Key: priv})
	require.NoError(t, err)
	b.WithClaim("role", "admin")

	sdJwt, err := b.Build()
	require.NoError(t, err)
	require.Equal(t, 1, strings.Count(sdJwt, "~"), "trailing separator only, no disclosures")

	payload, err := extractUnverifiedPayload(t, sdJwt)
	require.NoError(t, err)
	var claims map[string]any
	require.NoError(t, json.Unmarshal(payload, &claims))
	require.NotContains(t, claims, "_sd")
	require.NotContains(t, claims, "_sd_alg")
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

// decodeDisclosure decodes a disclosure segment's [salt, name, value] array
// and returns its name, value, and digest, for comparing against a signed
// JWT's "_sd" claim.
func decodeDisclosure(t *testing.T, encoded string) (name string, value any, digest string) {
	t.Helper()

	sum := sha256.Sum256([]byte(encoded))
	digest = base64.RawURLEncoding.EncodeToString(sum[:])

	raw, err := base64.RawURLEncoding.DecodeString(encoded)
	require.NoError(t, err)
	var arr []any
	require.NoError(t, json.Unmarshal(raw, &arr))
	require.Len(t, arr, 3)
	return arr[1].(string), arr[2], digest
}

// extractUnverifiedPayload decodes a compact SD-JWT's signed JWT segment's
// payload without verifying its signature, for assertions that don't need
// to also exercise signature verification.
func extractUnverifiedPayload(t *testing.T, sdJwt string) ([]byte, error) {
	t.Helper()
	parts := strings.Split(strings.SplitN(sdJwt, "~", 2)[0], ".")
	require.Len(t, parts, 3)
	return base64.RawURLEncoding.DecodeString(parts[1])
}

// newTestHolderKey generates a throwaway ES256 holder key for binding tests.
func newTestHolderKey(t *testing.T) jose.JSONWebKey {
	t.Helper()
	_, priv, err := generator.NewSigningKey(jose.ES256, 0)
	require.NoError(t, err)
	return jose.JSONWebKey{Key: priv, KeyID: "holder#1", Algorithm: string(jose.ES256), Use: "sig"}
}
