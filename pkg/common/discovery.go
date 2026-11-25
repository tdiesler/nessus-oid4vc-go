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

// CredentialConfigurationSupported ========================================================================================

// CredentialConfigurationSupported is one entry of a credential issuer's
// credential_configurations_supported map (OID4VCI): the format and
// verifiable credential type a holder receives under this id, and the
// scope that grants it.
type CredentialConfigurationSupported struct {
	Format string `json:"format"`
	Scope  string `json:"scope,omitempty"`
	Vct    string `json:"vct,omitempty"`
}

// CredentialIssuerMetadata =================================================================================================

// CredentialIssuerMetadata is the subset of an OID4VCI credential issuer
// metadata document (served at /.well-known/openid-credential-issuer) this
// project currently builds and consumes: which credential configurations
// this issuer can produce, keyed by credential_configuration_id, and the
// scope that grants each.
type CredentialIssuerMetadata struct {
	CredentialIssuer                  string                                      `json:"credential_issuer"`
	CredentialConfigurationsSupported map[string]CredentialConfigurationSupported `json:"credential_configurations_supported"`
}

// NewCredentialIssuerMetadata builds the credential issuer metadata
// document for issuer, from cfg's configured credential configurations and
// the scopes that grant them.
func NewCredentialIssuerMetadata(issuer string, cfg *AppConfig) *CredentialIssuerMetadata {

	scopeByConfigId := make(map[string]string, len(cfg.Scopes))
	for _, scope := range cfg.Scopes {
		for _, id := range scope.CredentialConfigurationIds {
			scopeByConfigId[id] = scope.Name
		}
	}

	supported := make(map[string]CredentialConfigurationSupported, len(cfg.CredentialConfigurations))
	for _, cc := range cfg.CredentialConfigurations {
		supported[cc.Id] = CredentialConfigurationSupported{
			Format: cc.Format,
			Scope:  scopeByConfigId[cc.Id],
			Vct:    cc.Vct,
		}
	}

	return &CredentialIssuerMetadata{
		CredentialIssuer:                  issuer,
		CredentialConfigurationsSupported: supported,
	}
}
