package oauth

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/tdiesler/nessus-oid4vc-go/pkg/config"
	"github.com/tdiesler/nessus-oid4vc-go/pkg/utils"
)

// Fixed by scripts/vault-setup's holder persona.
const (
	UserAlice    = "alice"
	UserPassword = "password"
)

// TestCodeFlowAuthorization drives Vault's own OIDC provider login page as
// Alice's wallet/user-agent would, redeems the resulting authorization code
// at the token endpoint, and expects back a real access token.
func TestCodeFlowAuthorization(t *testing.T) {
	cfg, err := config.GetAppConfig()
	require.NoError(t, err)

	// Complete the Authorization Code flow.
	authAccessor, err := NewOAuthAuthorizationAccessor()
	require.NoError(t, err)
	code, err := authAccessor.CodeFlowAuthorization(cfg.OidcClient, "openid profile", UserAlice, UserPassword)
	require.NoError(t, err)
	require.NotEmpty(t, code)

	// Redeem the code at the token endpoint.
	tokenAccessor, err := NewOAuthTokenAccessor()
	require.NoError(t, err)
	token, err := tokenAccessor.ExchangeAuthorizationCode(cfg.OidcClient, code, cfg.RedirectURI)
	require.NoError(t, err)
	require.NotEmpty(t, token.AccessToken)

	// Verify the id_token's signature and claims.
	discovery, err := NewWellKnownAccessor()
	require.NoError(t, err)
	metadata, err := discovery.AuthorizationServerMetadata()
	require.NoError(t, err)
	jwks, err := utils.FetchJWKS(http.DefaultClient, metadata.JwksUri)
	require.NoError(t, err)
	claims, err := utils.VerifyJWT(token.IdToken, jwks)
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
