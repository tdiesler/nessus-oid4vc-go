package common

// AuthorizationServerMetadata ==========================================================================================

// AuthorizationServerMetadata is the subset of an OAuth 2.0 / OpenID
// Connect discovery document (RFC 8414 / OpenID Connect Discovery 1.0)
// needed to locate an authorization server's endpoints, rather than
// assuming hardcoded paths.
type AuthorizationServerMetadata struct {
	Issuer                string   `json:"issuer"`
	AuthorizationEndpoint string   `json:"authorization_endpoint"`
	TokenEndpoint         string   `json:"token_endpoint"`
	UserinfoEndpoint      string   `json:"userinfo_endpoint"`
	EndSessionEndpoint    string   `json:"end_session_endpoint,omitempty"`
	RevocationEndpoint    string   `json:"revocation_endpoint,omitempty"`
	JwksUri               string   `json:"jwks_uri"`
	ScopesSupported       []string `json:"scopes_supported"`
}
