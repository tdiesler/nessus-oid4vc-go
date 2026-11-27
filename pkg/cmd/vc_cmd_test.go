package cmd

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	co "github.com/tdiesler/nessus-oid4vc-go/pkg/common"
	"github.com/tdiesler/nessus-oid4vc-go/pkg/holder"
	"github.com/tdiesler/nessus-oid4vc-go/pkg/oid4vci"
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

// TestVcGetRefreshesNearExpiryToken drives vc get against the vault
// flavor with a near-expiry access token, confirming pkg/holder's existing
// refreshSession/refreshToken path (see Wallet.GetCredential) redeems the
// stored refresh token for a rotated one and still returns the credential
// — now working against the vault flavor the same way it already does
// against Keycloak.
func TestVcGetRefreshesNearExpiryToken(t *testing.T) {
	iss := holder.IssuerVault

	snapshot := oid4vci.TakeWalletSnapshot(t, iss)
	defer func() { _ = snapshot.Restore() }()

	login := NewLoginOpts()
	login.Issuer = iss
	login.User = co.UserAlice
	login.Password = co.UserPassword
	login.Scope = "natural_person"
	require.NoError(t, login.Run())

	create := NewKeyCreateOpts()
	create.Issuer = iss
	create.User = co.UserAlice
	require.NoError(t, create.Run())

	w, err := holder.NewWallet(iss, co.UserAlice)
	require.NoError(t, err)
	conn := w.Issuer().Users[co.UserAlice]
	require.NotNil(t, conn)
	originalRefreshToken := conn.Token.RefreshToken
	require.NotEmpty(t, originalRefreshToken)

	conn.Token.ExpiresAt = time.Now()
	require.NoError(t, w.Save())

	get := NewVcGetOpts()
	get.Issuer = iss
	get.User = co.UserAlice
	get.CredentialIdentifier = "natural_person_sd_0000"
	require.NoError(t, get.Run())

	w, err = holder.NewWallet(iss, co.UserAlice)
	require.NoError(t, err)
	conn = w.Issuer().Users[co.UserAlice]
	require.NotNil(t, conn)
	require.NotEqual(t, originalRefreshToken, conn.Token.RefreshToken, "refresh must rotate the stored refresh token")
	require.False(t, conn.Token.Expired())
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
