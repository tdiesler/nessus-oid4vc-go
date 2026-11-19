package oauth

import (
	"fmt"
	"net/http"

	co "github.com/tdiesler/nessus-oid4vc-go/pkg/common"
)

// Well-known suffixes to try, in order. OpenID Connect Discovery 1.0 and
// OAuth 2.0 Authorization Server Metadata (RFC 8414) define two different,
// commonly-aliased documents; not every authorization server serves both
// (Vault's Identity OIDC provider, for one, only serves the former).
var wellKnownSuffixes = []string{
	"/.well-known/openid-configuration",
	"/.well-known/oauth-authorization-server",
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
func (d *WellKnownAccessor) AuthorizationServerMetadata() (*co.AuthorizationServerMetadata, error) {
	cfg, err := co.GetAppConfig()
	if err != nil {
		return nil, err
	}
	var lastErr error
	for _, suffix := range wellKnownSuffixes {
		issuer := "/v1/identity/oidc/provider/" + cfg.OidcProvider
		req := co.NewHttpGetRequest(cfg.VaultAddr + issuer + suffix)
		metadata, err := req.Fetch[co.AuthorizationServerMetadata](d.httpClient)
		if err != nil {
			lastErr = err
			continue
		}
		return &metadata, nil
	}
	return nil, fmt.Errorf("cannot discover authorization metadata: %w", lastErr)
}

// Private -------------------------------------------------------------------------------------------------------------
