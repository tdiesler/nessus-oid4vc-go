package oid4vci

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/tdiesler/nessus-oid4vc-go/pkg/config"
)

// Well-known suffixes to try, in order. OpenID Connect Discovery 1.0 and
// OAuth 2.0 Authorization Server Metadata (RFC 8414) define two different,
// commonly-aliased documents; not every authorization server serves both
// (Vault's Identity OIDC provider, for one, only serves the former).
var wellKnownSuffixes = []string{
	"/.well-known/openid-configuration",
	"/.well-known/oauth-authorization-server",
}

// AuthorizationServerMetadata is the subset of an authorization server's
// discovery document the issuer service needs to locate its endpoints,
// rather than assuming hardcoded paths.
type AuthorizationServerMetadata struct {
	Issuer                string   `json:"issuer"`
	AuthorizationEndpoint string   `json:"authorization_endpoint"`
	TokenEndpoint         string   `json:"token_endpoint"`
	JwksUri               string   `json:"jwks_uri"`
	ScopesSupported       []string `json:"scopes_supported"`
}

// WellKnownMetadataAccessor fetches an authorization server's metadata document.
type WellKnownMetadataAccessor struct {
	httpClient *http.Client
}

// NewWellKnownMetadataAccessor constructs a WellKnownMetadataAccessor.
func NewWellKnownMetadataAccessor() (*WellKnownMetadataAccessor, error) {
	return &WellKnownMetadataAccessor{httpClient: http.DefaultClient}, nil
}

// Discover fetches issuer's metadata document, trying each well-known
// suffix in turn and returning the first one found.
func (d *WellKnownMetadataAccessor) Discover() (*AuthorizationServerMetadata, error) {
	cfg, err := config.GetAppConfig()
	if err != nil {
		return nil, err
	}
	var lastErr error
	for _, suffix := range wellKnownSuffixes {
		issuer := cfg.VaultAddr + "/v1/identity/oidc/provider/" + cfg.OIDCProvider
		metadata, err := d.fetch(issuer + suffix)
		if err != nil {
			lastErr = err
			continue
		}
		return metadata, nil
	}
	return nil, fmt.Errorf("cannot discover authorization metadata: %w", lastErr)
}

// Private -------------------------------------------------------------------------------------------------------------

func (d *WellKnownMetadataAccessor) fetch(url string) (*AuthorizationServerMetadata, error) {
	resp, err := d.httpClient.Get(url)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GET %s: %s", url, resp.Status)
	}

	var metadata AuthorizationServerMetadata
	if err := json.NewDecoder(resp.Body).Decode(&metadata); err != nil {
		return nil, fmt.Errorf("GET %s: decode response: %w", url, err)
	}
	return &metadata, nil
}
