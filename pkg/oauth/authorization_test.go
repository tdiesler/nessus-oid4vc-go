package oauth

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"
	co "github.com/tdiesler/nessus-oid4vc-go/pkg/common"
)

// TestCodeFlowAuthorization drives Vault's own OIDC provider login page as
// Alice's holder/user-agent would, redeems the resulting authorization code
// at the token endpoint, and expects back a real access token whose
// id_token verifies against Vault's own JWKS.
func TestCodeFlowAuthorization(t *testing.T) {
	cfg, err := co.GetAppConfig()
	require.NoError(t, err)

	// Complete the Authorization Code flow.
	authAccessor, err := NewAuthorizationAccessor()
	require.NoError(t, err)
	code, err := authAccessor.CodeFlowAuthorization(cfg.OidcClient, "openid", co.UserAlice, co.UserPassword)
	require.NoError(t, err)
	require.NotEmpty(t, code)

	// Redeem the code at the token endpoint.
	tokenAccessor, err := NewTokenAccessor()
	require.NoError(t, err)
	token, err := tokenAccessor.ExchangeAuthorizationCode(cfg.OidcClient, code, cfg.RedirectUri)
	require.NoError(t, err)
	require.NotEmpty(t, token.AccessToken)

	// Verify the id_token's signature.
	discovery, err := NewWellKnownAccessor()
	require.NoError(t, err)
	metadata, err := discovery.AuthorizationServerMetadata()
	require.NoError(t, err)
	jwks, err := co.FetchJWKS(http.DefaultClient, metadata.JwksUri)
	require.NoError(t, err)
	claims, err := co.VerifyJWT(token.IdToken, jwks)
	require.NoError(t, err)
	require.NotEmpty(t, claims["sub"])

	// Confirm the UserInfo endpoint resolves the same subject.
	userinfoAccessor, err := NewUserInfoAccessor()
	require.NoError(t, err)
	userinfoClaims, err := userinfoAccessor.Fetch(metadata.UserinfoEndpoint, token.AccessToken)
	require.NoError(t, err)
	require.Equal(t, claims["sub"], userinfoClaims["sub"])
}
