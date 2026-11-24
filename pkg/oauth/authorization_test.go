package oauth

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"
	co "github.com/tdiesler/nessus-oid4vc-go/pkg/common"
)

// TestCodeFlowAuthorization drives Vault's own OIDC provider login page as
// Alice's holder/user-agent would, redeems the resulting authorization code
// at the token endpoint, and expects back a real access token.
func TestCodeFlowAuthorization(t *testing.T) {
	cfg, err := co.GetAppConfig()
	require.NoError(t, err)

	// Complete the Authorization Code flow.
	authAccessor, err := NewAuthorizationAccessor()
	require.NoError(t, err)
	code, err := authAccessor.CodeFlowAuthorization(cfg.OidcClient, "openid profile", co.UserAlice, co.UserPassword)
	require.NoError(t, err)
	require.NotEmpty(t, code)

	// Redeem the code at the token endpoint.
	tokenAccessor, err := NewTokenAccessor()
	require.NoError(t, err)
	token, err := tokenAccessor.ExchangeAuthorizationCode(cfg.OidcClient, code, cfg.RedirectUri)
	require.NoError(t, err)
	require.NotEmpty(t, token.AccessToken)

	// Verify the id_token's signature and claims.
	discovery, err := NewWellKnownAccessor()
	require.NoError(t, err)
	metadata, err := discovery.AuthorizationServerMetadata()
	require.NoError(t, err)
	jwks, err := co.FetchJWKS(http.DefaultClient, metadata.JwksUri)
	require.NoError(t, err)
	claims, err := co.VerifyJWT(token.IdToken, jwks)
	require.NoError(t, err)
	require.Equal(t, "Alice", claims["firstName"])
	require.Equal(t, "Wonderland", claims["familyName"])
	require.Equal(t, "alice@email.com", claims["email"])

	// Confirm the same claims via the UserInfo endpoint.
	userinfoAccessor, err := NewUserInfoAccessor()
	require.NoError(t, err)
	userinfoClaims, err := userinfoAccessor.Fetch(metadata.UserinfoEndpoint, token.AccessToken)
	require.NoError(t, err)
	require.Equal(t, "Alice", userinfoClaims["firstName"])
	require.Equal(t, "Wonderland", userinfoClaims["familyName"])
	require.Equal(t, "alice@email.com", userinfoClaims["email"])
}
