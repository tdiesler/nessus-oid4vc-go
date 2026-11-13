package oid4vci

import (
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/tdiesler/nessus-oid4vc-go/pkg/config"
)

// TestDiscoverAuthorizationServerMetadata discovers the already-registered
// "oid4vc" OIDC provider's metadata document from Vault.
// Vault serves OIDC Discovery (not RFC 8414), and its authorization_endpoint
// points at the UI route, not the raw /v1 API path.
func TestDiscoverAuthorizationServerMetadata(t *testing.T) {
	cfg, err := config.GetAppConfig()
	require.NoError(t, err)

	accessor, err := NewWellKnownMetadataAccessor()
	require.NoError(t, err)

	metadata, err := accessor.Discover()
	require.NoError(t, err)

	issuerEndpoint := cfg.VaultAddr + "/v1/identity/oidc/provider/" + cfg.OIDCProvider
	uiEndpoint := cfg.VaultAddr + "/ui/vault/identity/oidc/provider/" + cfg.OIDCProvider
	require.Equal(t, issuerEndpoint, metadata.Issuer)
	require.Equal(t, uiEndpoint+"/authorize", metadata.AuthorizationEndpoint)
	require.Equal(t, issuerEndpoint+"/token", metadata.TokenEndpoint)
	require.Equal(t, issuerEndpoint+"/.well-known/keys", metadata.JwksUri)
	require.Contains(t, metadata.ScopesSupported, "profile")
}
