package oid4vci

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jose-util/generator"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/stretchr/testify/require"
	co "github.com/tdiesler/nessus-oid4vc-go/pkg/common"
	"github.com/tdiesler/nessus-oid4vc-go/pkg/vault"
)

// TestAuthorizedCredentialConfigurationId checks the Credential Endpoint's
// authorization barrier: an access token may resolve a
// credential_configuration_id for a credential_identifier its own
// authorization_details actually name, and nothing else.
func TestAuthorizedCredentialConfigurationId(t *testing.T) {

	oauth, err := NewOAuthClient()
	require.NoError(t, err)
	oauth.WithScope("natural_person")

	code, err := oauth.Authorize(co.UserAlice, co.UserPassword)
	require.NoError(t, err)
	token, err := oauth.ExchangeCode(code)
	require.NoError(t, err)

	configId, err := authServer.AuthorizedCredentialConfigurationId(token.AccessToken, "natural_person_sd_0000")
	require.NoError(t, err)
	require.Equal(t, "natural_person_sd", configId)

	configId, err = authServer.AuthorizedCredentialConfigurationId(token.AccessToken, "natural_person_jwt_0000")
	require.NoError(t, err)
	require.Equal(t, "natural_person_jwt", configId)

	_, err = authServer.AuthorizedCredentialConfigurationId(token.AccessToken, "not_a_granted_identifier")
	require.Error(t, err)

	_, err = authServer.AuthorizedCredentialConfigurationId("not-a-real-access-token", "natural_person_sd_0000")
	require.Error(t, err)
}

// TestAuthorizationDetails requests the natural_person scope at login and
// checks the token response's authorization_details names both credential
// configurations that scope grants (config/oid4vc-config.yml), each with
// its single credential_identifier.
func TestAuthorizationDetails(t *testing.T) {

	oauth, err := NewOAuthClient()
	require.NoError(t, err)
	oauth.WithScope("natural_person")

	code, err := oauth.Authorize(co.UserAlice, co.UserPassword)
	require.NoError(t, err)

	token, err := oauth.ExchangeCode(code)
	require.NoError(t, err)

	require.ElementsMatch(t, []AuthorizationDetail{
		{Type: "openid_credential", CredentialConfigurationId: "natural_person_sd", CredentialIdentifiers: []string{"natural_person_sd_0000"}},
		{Type: "openid_credential", CredentialConfigurationId: "natural_person_jwt", CredentialIdentifiers: []string{"natural_person_jwt_0000"}},
	}, token.AuthorizationDetails)
}

// TestOAuthAuthorization drives this server's own Authorization Code flow
// as Alice's holder would — POST /authorize with her credentials, redeem
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

// TestIssueCredential drives the Credential Endpoint end to end over real
// HTTP: login, token exchange, nonce, and credential request, then checks
// the returned SD-JWT VC verifies against /jwks.json, discloses exactly
// Alice's declared Vault KV claims (config/oid4vc-config.yml) with digests
// that match, and binds the holder key the request proved possession of.
// It also checks the jwt_vc_json sibling configuration is rejected, since
// only dc+sd-jwt is supported at this endpoint.
func TestIssueCredential(t *testing.T) {

	cfg, err := co.GetAppConfig()
	require.NoError(t, err)

	oauth, err := NewOAuthClient()
	require.NoError(t, err)
	oauth.WithScope("natural_person")

	code, err := oauth.Authorize(co.UserAlice, co.UserPassword)
	require.NoError(t, err)
	token, err := oauth.ExchangeCode(code)
	require.NoError(t, err)

	_, holderKey, err := generator.NewSigningKey(jose.ES256, 0)
	require.NoError(t, err)

	nonce, err := oauth.FetchNonce()
	require.NoError(t, err)
	proof := buildTestKeyProof(t, holderKey, cfg.OidcClient, testIssuer, nonce)

	sdJwt, err := oauth.FetchCredential(token.AccessToken, "natural_person_sd_0000", proof)
	require.NoError(t, err)

	parts := strings.Split(sdJwt, "~")
	require.Len(t, parts, 6, "signed JWT, 4 disclosures (id/email/firstName/familyName), trailing empty segment")
	require.Empty(t, parts[5])

	jwks, err := oauth.FetchJWKS()
	require.NoError(t, err)
	require.Len(t, jwks.Keys, 1)

	sig, err := jose.ParseSigned(parts[0], []jose.SignatureAlgorithm{jose.ES256})
	require.NoError(t, err)
	payload, err := sig.Verify(jwks.Keys[0].Key)
	require.NoError(t, err)

	var claims map[string]any
	require.NoError(t, json.Unmarshal(payload, &claims))
	require.Equal(t, "NaturalPerson", claims["vct"])
	require.Equal(t, testIssuer, claims["iss"])
	require.Equal(t, co.UserAlice, claims["sub"])

	cnf, ok := claims["cnf"].(map[string]any)
	require.True(t, ok)
	jwk, ok := cnf["jwk"].(map[string]any)
	require.True(t, ok)
	require.NotContains(t, jwk, "d", "cnf.jwk must carry the holder's public key only")

	wantClaims := map[string]string{"id": co.UserAlice, "email": "alice@email.com", "firstName": "Alice", "familyName": "Wonderland"}
	sdDigests, ok := claims["_sd"].([]any)
	require.True(t, ok)
	require.Len(t, sdDigests, len(wantClaims))

	for _, disclosure := range parts[1:5] {
		raw, err := base64.RawURLEncoding.DecodeString(disclosure)
		require.NoError(t, err)
		var arr []any
		require.NoError(t, json.Unmarshal(raw, &arr))
		require.Len(t, arr, 3)
		name, value := arr[1].(string), arr[2]
		require.Equal(t, wantClaims[name], value)
		require.Contains(t, sdDigests, digestDisclosure(disclosure))
	}

	// jwt_vc_json isn't supported at this endpoint.
	nonce, err = oauth.FetchNonce()
	require.NoError(t, err)
	proof = buildTestKeyProof(t, holderKey, cfg.OidcClient, testIssuer, nonce)
	_, err = oauth.FetchCredential(token.AccessToken, "natural_person_jwt_0000", proof)
	require.Error(t, err)
}

// TestIssueNonceAndVerifyKeyProof mints a c_nonce via IssueNonce, builds a
// holder's self-signed OID4VCI key-proof JWT around it the way
// pkg/holder's buildProofJWT does, and checks VerifyKeyProof accepts a
// valid proof, returns the embedded holder key, and consumes the nonce
// exactly once.
func TestIssueNonceAndVerifyKeyProof(t *testing.T) {

	cfg, err := co.GetAppConfig()
	require.NoError(t, err)

	holderPub, holderKey, err := generator.NewSigningKey(jose.ES256, 0)
	require.NoError(t, err)

	nonce, err := authServer.IssueNonce()
	require.NoError(t, err)

	proof := buildTestKeyProof(t, holderKey, cfg.OidcClient, testIssuer, nonce)

	verifiedKey, err := authServer.VerifyKeyProof(cfg.OidcClient, proof)
	require.NoError(t, err)
	require.Equal(t, holderPub, verifiedKey.Key)

	// the nonce is single-use: replaying the same proof fails
	_, err = authServer.VerifyKeyProof(cfg.OidcClient, proof)
	require.Error(t, err)
}

// TestVerifyKeyProofRejectsInvalidProofs checks VerifyKeyProof rejects a
// proof naming an unknown nonce, the wrong audience, or the wrong client.
func TestVerifyKeyProofRejectsInvalidProofs(t *testing.T) {

	cfg, err := co.GetAppConfig()
	require.NoError(t, err)

	_, holderKey, err := generator.NewSigningKey(jose.ES256, 0)
	require.NoError(t, err)

	proof := buildTestKeyProof(t, holderKey, cfg.OidcClient, testIssuer, "not-a-real-nonce")
	_, err = authServer.VerifyKeyProof(cfg.OidcClient, proof)
	require.Error(t, err)

	nonce, err := authServer.IssueNonce()
	require.NoError(t, err)
	proof = buildTestKeyProof(t, holderKey, cfg.OidcClient, "https://wrong-issuer.test", nonce)
	_, err = authServer.VerifyKeyProof(cfg.OidcClient, proof)
	require.Error(t, err)

	nonce, err = authServer.IssueNonce()
	require.NoError(t, err)
	proof = buildTestKeyProof(t, holderKey, "wrong-client", testIssuer, nonce)
	_, err = authServer.VerifyKeyProof(cfg.OidcClient, proof)
	require.Error(t, err)
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

// Private ---------------------------------------------------------------------------------------------------------------

// buildTestKeyProof builds a holder's self-signed OID4VCI key-proof JWT —
// the same shape pkg/holder's buildProofJWT produces — around holderKey,
// naming clientId as its issuer, audience as its audience, and nonce as
// its anti-replay nonce.
func buildTestKeyProof(t *testing.T, holderKey any, clientId, audience, nonce string) string {
	t.Helper()

	opts := (&jose.SignerOptions{EmbedJWK: true}).WithType(keyProofType)
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: holderKey}, opts)
	require.NoError(t, err)

	claims := jwt.Claims{
		Issuer:   clientId,
		Audience: jwt.Audience{audience},
		IssuedAt: jwt.NewNumericDate(time.Now()),
	}
	proof, err := jwt.Signed(signer).Claims(claims).Claims(map[string]any{"nonce": nonce}).Serialize()
	require.NoError(t, err)
	return proof
}

// digestDisclosure returns encoded's SD-JWT digest — base64url(sha256(ASCII(encoded)))
// — for comparing a disclosure segment against a signed JWT's "_sd" claim.
func digestDisclosure(encoded string) string {
	sum := sha256.Sum256([]byte(encoded))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}
