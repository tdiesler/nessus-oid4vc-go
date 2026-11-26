package cmd

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestDecodeDisclosure checks decodeDisclosure recovers an SD-JWT
// disclosure's [salt, claim name, claim value] array.
func TestDecodeDisclosure(t *testing.T) {
	encoded := encodeJSONSegment(t, []any{"salt123", "email", "alice@email.com"})

	arr, err := decodeDisclosure(encoded)
	require.NoError(t, err)
	require.Equal(t, []any{"salt123", "email", "alice@email.com"}, arr)
}

// TestDecodeJWT checks decodeJWT recovers a compact JWT's header and
// payload without needing — or checking — its signature.
func TestDecodeJWT(t *testing.T) {
	header := encodeJSONSegment(t, map[string]any{"alg": "ES256", "typ": "dc+sd-jwt"})
	payload := encodeJSONSegment(t, map[string]any{"iss": "https://issuer.test", "vct": "NaturalPerson"})
	token := header + "." + payload + ".signature"

	gotHeader, gotPayload, err := decodeJWT(token)
	require.NoError(t, err)
	require.Equal(t, map[string]any{"alg": "ES256", "typ": "dc+sd-jwt"}, gotHeader)
	require.Equal(t, map[string]any{"iss": "https://issuer.test", "vct": "NaturalPerson"}, gotPayload)
}

// TestDecodeJWTRejectsWrongSegmentCount checks decodeJWT rejects a string
// that isn't a 3-segment compact JWT.
func TestDecodeJWTRejectsWrongSegmentCount(t *testing.T) {
	_, _, err := decodeJWT("not-a-jwt")
	require.Error(t, err)
}

// TestDigestDisclosure checks digestDisclosure computes an SD-JWT
// disclosure's digest as base64url(sha256(ASCII(encoded))).
func TestDigestDisclosure(t *testing.T) {
	encoded := encodeJSONSegment(t, []any{"salt123", "email", "alice@email.com"})

	sum := sha256.Sum256([]byte(encoded))
	require.Equal(t, base64.RawURLEncoding.EncodeToString(sum[:]), digestDisclosure(encoded))
}

// TestFormatDisclosure checks formatDisclosure renders a string claim
// value bare (unquoted) and a non-string value JSON-encoded, matching
// scripts/keycloak-functions' decode_vc.
func TestFormatDisclosure(t *testing.T) {
	require.Equal(t, `["salt123", "email", alice@email.com]`, formatDisclosure([]any{"salt123", "email", "alice@email.com"}))
	require.Equal(t, `["salt123", "verified", true]`, formatDisclosure([]any{"salt123", "verified", true}))
}

// Private ---------------------------------------------------------------------------------------------------------------

// encodeJSONSegment JSON-marshals v and base64url-encodes it, the way a
// JWT/disclosure segment is encoded.
func encodeJSONSegment(t *testing.T, v any) string {
	t.Helper()
	data, err := json.Marshal(v)
	require.NoError(t, err)
	return base64.RawURLEncoding.EncodeToString(data)
}
