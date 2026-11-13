package oauth

import (
	"fmt"
	"net/http"

	"github.com/tdiesler/nessus-oid4vc-go/pkg/config"
	"github.com/tdiesler/nessus-oid4vc-go/pkg/utils"
)

// Well-known suffixes to try, in order. OpenID Connect Discovery 1.0 and
// OAuth 2.0 Authorization Server Metadata (RFC 8414) define two different,
// commonly-aliased documents; not every authorization server serves both
// (Vault's Identity OIDC provider, for one, only serves the former).
var wellKnownSuffixes = []string{
	"/.well-known/openid-configuration",
	"/.well-known/oauth-authorization-server",
}

// AuthorizationServerMetadata =========================================================================================

// AuthorizationServerMetadata is the subset of an authorization server's
// discovery document the issuer service needs to locate its endpoints,
// rather than assuming hardcoded paths.
type AuthorizationServerMetadata struct {
	Issuer                string   `json:"issuer"`
	AuthorizationEndpoint string   `json:"authorization_endpoint"`
	TokenEndpoint         string   `json:"token_endpoint"`
	UserinfoEndpoint      string   `json:"userinfo_endpoint"`
	JwksUri               string   `json:"jwks_uri"`
	ScopesSupported       []string `json:"scopes_supported"`
}

// WellKnownAccessor ===================================================================================================

// WellKnownAccessor fetches an authorization server's metadata document.
type WellKnownAccessor struct {
	httpClient *http.Client
}

// NewWellKnownAccessor constructs a WellKnownAccessor.
func NewWellKnownAccessor() (*WellKnownAccessor, error) {
	return &WellKnownAccessor{httpClient: http.DefaultClient}, nil
}

// AuthorizationServerMetadata fetches issuer's metadata document, trying each well-known
// suffix in turn and returning the first one found.
func (d *WellKnownAccessor) AuthorizationServerMetadata() (*AuthorizationServerMetadata, error) {
	cfg, err := config.GetAppConfig()
	if err != nil {
		return nil, err
	}
	var lastErr error
	for _, suffix := range wellKnownSuffixes {
		issuer := "/v1/identity/oidc/provider/" + cfg.OidcProvider
		req := utils.NewHttpGetRequest(cfg.VaultAddr + issuer + suffix)
		metadata, err := req.Fetch[AuthorizationServerMetadata](d.httpClient)
		if err != nil {
			lastErr = err
			continue
		}
		return &metadata, nil
	}
	return nil, fmt.Errorf("cannot discover authorization metadata: %w", lastErr)
}

// Private -------------------------------------------------------------------------------------------------------------
