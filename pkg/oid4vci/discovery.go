package oid4vci

import co "github.com/tdiesler/nessus-oid4vc-go/pkg/common"

// Metadata =================================================================================================================

// Metadata is this authorization server's own OAuth 2.0 / OpenID Connect
// discovery document (RFC 8414 / OIDC Discovery 1.0), served at
// /.well-known/openid-configuration.
type Metadata struct {
	Issuer                 string   `json:"issuer"`
	AuthorizationEndpoint  string   `json:"authorization_endpoint"`
	TokenEndpoint          string   `json:"token_endpoint"`
	UserinfoEndpoint       string   `json:"userinfo_endpoint"`
	RevocationEndpoint     string   `json:"revocation_endpoint"`
	JwksUri                string   `json:"jwks_uri"`
	ScopesSupported        []string `json:"scopes_supported"`
	ResponseTypesSupported []string `json:"response_types_supported"`
	GrantTypesSupported    []string `json:"grant_types_supported"`
}

// NewMetadata constructs the discovery document for an authorization server
// whose base URL is issuer, with ScopesSupported built from cfg's
// configured scopes (see pkg/common.ScopeConfig) — this server's own
// scopes, not Vault's unrelated OIDC provider scopes (see pkg/oauth).
func NewMetadata(issuer string, cfg *co.AppConfig) *Metadata {
	scopesSupported := make([]string, 0, len(cfg.Scopes)+1)
	scopesSupported = append(scopesSupported, "openid")
	for _, scope := range cfg.Scopes {
		scopesSupported = append(scopesSupported, scope.Name)
	}

	return &Metadata{
		Issuer:                 issuer,
		AuthorizationEndpoint:  issuer + "/authorize",
		TokenEndpoint:          issuer + "/token",
		UserinfoEndpoint:       issuer + "/userinfo",
		RevocationEndpoint:     issuer + "/revoke",
		JwksUri:                issuer + "/jwks.json",
		ScopesSupported:        scopesSupported,
		ResponseTypesSupported: []string{"code"},
		GrantTypesSupported:    []string{"authorization_code", "refresh_token"},
	}
}
