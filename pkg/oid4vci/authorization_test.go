package oid4vci

import (
	"testing"

	"github.com/stretchr/testify/require"
	co "github.com/tdiesler/nessus-oid4vc-go/pkg/common"
	"github.com/tdiesler/nessus-oid4vc-go/pkg/vault"
)

// TestOAuthAuthorization drives this server's own Authorization Code flow
// as Alice's wallet would — POST /authorize with her credentials, redeem
// the resulting code at /token — and expects back an access_token plus an
// id_token that verifies against this server's own /jwks.json.
func TestOAuthAuthorization(t *testing.T) {

	oauth, err := NewOAuthClient()
	require.NoError(t, err)

	code, err := oauth.Authorize(co.UserAlice, co.UserPassword)
	require.NoError(t, err)

	token, err := oauth.ExchangeCode(code)
	require.NoError(t, err)
	require.NotEmpty(t, token.AccessToken)
	require.NotEmpty(t, token.IdToken)

	jwks, err := oauth.FetchJWKS()
	require.NoError(t, err)
	claims, err := co.VerifyJWT(token.IdToken, jwks)
	require.NoError(t, err)
	require.Equal(t, testIssuer, claims["iss"])
	require.Equal(t, co.UserAlice, claims["sub"])
}

// TestLogout exercises Logout end-to-end: revoking the session's
// underlying Vault token via Vault's own revoke-self endpoint, and
// removing the session so the access token itself stops working too.
func TestLogout(t *testing.T) {
	oauth, err := NewOAuthClient()
	require.NoError(t, err)

	code, err := oauth.Authorize(co.UserAlice, co.UserPassword)
	require.NoError(t, err)
	token, err := oauth.ExchangeCode(code)
	require.NoError(t, err)

	_, err = authServer.ReadSubjectsKeyValueClaims(token.AccessToken)
	require.NoError(t, err)

	require.NoError(t, authServer.Logout(token.AccessToken))

	_, err = authServer.ReadSubjectsKeyValueClaims(token.AccessToken)
	require.Error(t, err)
}

// TestUserInfoClaims resolves an access token back to Alice's claims,
// sourced from Vault KV — not Vault's identity entity metadata, which is
// all Vault's own OIDC scope templates could ever reach (see issue #17).
func TestUserInfoClaims(t *testing.T) {
	client, err := NewOAuthClient()
	require.NoError(t, err)

	code, err := client.Authorize(co.UserAlice, co.UserPassword)
	require.NoError(t, err)
	token, err := client.ExchangeCode(code)
	require.NoError(t, err)

	claims, err := client.UserInfo(token.AccessToken)
	require.NoError(t, err)
	require.Equal(t, "Alice", claims["firstName"])
	require.Equal(t, "Wonderland", claims["familyName"])
	require.Equal(t, "alice@email.com", claims["email"])
}

// TestEntityDataAccess resolves an oauth-proxy access token back to Alice's
// own Identity entity properties — reached here the same way pkg/vault's
// TestEntityDataAccess reaches it with a native Vault token, just
// translated through the proxy first.
func TestEntityDataAccess(t *testing.T) {
	oauth, err := NewOAuthClient()
	require.NoError(t, err)

	code, err := oauth.Authorize(co.UserAlice, co.UserPassword)
	require.NoError(t, err)
	token, err := oauth.ExchangeCode(code)
	require.NoError(t, err)

	entity, err := authServer.ReadSubjectsEntityClaims(token.AccessToken)
	require.NoError(t, err)
	require.Equal(t, co.UserAlice, entity.Name)
	require.Equal(t, "Alice", entity.Metadata["firstName"])
	require.Equal(t, "Wonderland", entity.Metadata["familyName"])
	require.Equal(t, "alice@email.com", entity.Metadata["email"])
}

// TestKeyValueDataAccess resolves an oauth-proxy access token back to
// Alice's own KV claims via ReadSubjectsKeyValueClaims — the same vault
// path pkg/vault's TestKeyValueDataAccess reaches with a native Vault
// token, just translated through the proxy first, and called directly
// rather than through the /userinfo endpoint TestUserInfoClaims exercises.
func TestKeyValueDataAccess(t *testing.T) {
	oauth, err := NewOAuthClient()
	require.NoError(t, err)

	code, err := oauth.Authorize(co.UserAlice, co.UserPassword)
	require.NoError(t, err)
	token, err := oauth.ExchangeCode(code)
	require.NoError(t, err)

	claims, err := authServer.ReadSubjectsKeyValueClaims(token.AccessToken)
	require.NoError(t, err)
	require.Equal(t, co.UserAlice, claims["id"])
	require.Equal(t, "Alice", claims["firstName"])
	require.Equal(t, "Wonderland", claims["familyName"])
	require.Equal(t, "alice@email.com", claims["email"])
}

// TestCrossEntityDataAccess mirrors pkg/vault's TestCrossEntityDataAccess
// through the oauth proxy: Max (the issuer) writes an offer to Alice's
// offer path using his own oauth-proxy access token, and Alice reads it
// back with hers — authServer translates each token to the real Vault
// token backing it, and the same Vault ACLs as the native path enforce who
// may read/write which path.
func TestCrossEntityDataAccess(t *testing.T) {
	oauth, err := NewOAuthClient()
	require.NoError(t, err)

	// Max writes an offer to Alice's offer path.
	code, err := oauth.Authorize(co.UserMax, co.UserPassword)
	require.NoError(t, err)
	maxToken, err := oauth.ExchangeCode(code)
	require.NoError(t, err)

	offer := map[string]any{"message": "You have a pending credential offer", "issuedBy": co.UserMax}
	err = authServer.WriteKeyValueClaims(maxToken.AccessToken, vault.SecretsPathOffers, co.UserAlice, offer)
	require.NoError(t, err)

	// Max cannot read the offer back himself.
	_, err = authServer.ReadKeyValueClaims(maxToken.AccessToken, vault.SecretsPathOffers, co.UserAlice)
	require.Error(t, err)

	// Alice reads the offer using her own oauth-proxy access token.
	code, err = oauth.Authorize(co.UserAlice, co.UserPassword)
	require.NoError(t, err)
	aliceToken, err := oauth.ExchangeCode(code)
	require.NoError(t, err)

	claims, err := authServer.ReadKeyValueClaims(aliceToken.AccessToken, vault.SecretsPathOffers, co.UserAlice)
	require.NoError(t, err)
	require.Equal(t, offer["message"], claims["message"])
	require.Equal(t, offer["issuedBy"], claims["issuedBy"])

	// Alice cannot write to her own offer path.
	err = authServer.WriteKeyValueClaims(aliceToken.AccessToken, vault.SecretsPathOffers, co.UserAlice, offer)
	require.Error(t, err)
}
