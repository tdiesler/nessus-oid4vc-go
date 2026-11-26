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

// ClaimMetadata ===========================================================================================================

// ClaimMetadata names one claim a credential configuration discloses, by
// its path into the credential's claim structure — flat for an SD-JWT VC,
// nested under "credentialSubject" for a jwt_vc_json credential.
type ClaimMetadata struct {
	Path      []string `json:"path"`
	Mandatory bool     `json:"mandatory,omitempty"`
}

// CredentialMetadataSupported =============================================================================================

// CredentialMetadataSupported is a credential configuration's
// credential_metadata: the claims it carries.
type CredentialMetadataSupported struct {
	Claims []ClaimMetadata `json:"claims,omitempty"`
}

// CredentialDefinition ====================================================================================================

// CredentialDefinition names a jwt_vc_json credential's W3C Verifiable
// Credential types — the format's analog of an SD-JWT VC's "vct".
type CredentialDefinition struct {
	Type []string `json:"type"`
}

// ProofTypeSupported ======================================================================================================

// ProofTypeSupported is one proof type (e.g. "jwt") this issuer accepts at
// its Credential Endpoint, naming the signing algorithms it verifies.
type ProofTypeSupported struct {
	ProofSigningAlgValuesSupported []string `json:"proof_signing_alg_values_supported"`
}

// CredentialConfigurationSupported ========================================================================================

// CredentialConfigurationSupported is one entry of a credential issuer's
// credential_configurations_supported map (OID4VCI): the format and
// verifiable credential type a holder receives under this id, the scope
// that grants it, and the issuer's actual signing/proof/claim capabilities
// for it.
type CredentialConfigurationSupported struct {
	Format                               string                        `json:"format"`
	Scope                                string                        `json:"scope,omitempty"`
	Vct                                  string                        `json:"vct,omitempty"`
	CryptographicBindingMethodsSupported []string                      `json:"cryptographic_binding_methods_supported,omitempty"`
	CredentialSigningAlgValuesSupported  []string                      `json:"credential_signing_alg_values_supported,omitempty"`
	ProofTypesSupported                  map[string]ProofTypeSupported `json:"proof_types_supported,omitempty"`
	CredentialDefinition                 *CredentialDefinition         `json:"credential_definition,omitempty"`
	CredentialMetadata                   *CredentialMetadataSupported  `json:"credential_metadata,omitempty"`
}

// CredentialIssuerMetadata =================================================================================================

// CredentialIssuerMetadata is the subset of an OID4VCI credential issuer
// metadata document (served at /.well-known/openid-credential-issuer) this
// project currently builds and consumes: this issuer's Credential and
// Nonce Endpoints, the authorization server(s) that protect them, and
// which credential configurations this issuer can produce, keyed by
// credential_configuration_id.
type CredentialIssuerMetadata struct {
	CredentialIssuer                  string                                      `json:"credential_issuer"`
	CredentialEndpoint                string                                      `json:"credential_endpoint"`
	NonceEndpoint                     string                                      `json:"nonce_endpoint,omitempty"`
	AuthorizationServers              []string                                    `json:"authorization_servers,omitempty"`
	CredentialConfigurationsSupported map[string]CredentialConfigurationSupported `json:"credential_configurations_supported"`
}

// NewCredentialIssuerMetadata builds the credential issuer metadata
// document for issuer, from cfg's configured credential configurations and
// the scopes that grant them. issuer is also this document's sole
// authorization server: this service's oid4vci.CredentialIssuer is both.
func NewCredentialIssuerMetadata(issuer string, cfg *AppConfig) *CredentialIssuerMetadata {

	scopeByConfigId := make(map[string]string, len(cfg.Scopes))
	for _, scope := range cfg.Scopes {
		for _, id := range scope.CredentialConfigurationIds {
			scopeByConfigId[id] = scope.Name
		}
	}

	supported := make(map[string]CredentialConfigurationSupported, len(cfg.CredentialConfigurations))
	for _, cc := range cfg.CredentialConfigurations {
		supported[cc.Id] = newCredentialConfigurationSupported(cc, scopeByConfigId[cc.Id])
	}

	return &CredentialIssuerMetadata{
		CredentialIssuer:                  issuer,
		CredentialEndpoint:                issuer + "/credential",
		NonceEndpoint:                     issuer + "/nonce",
		AuthorizationServers:              []string{issuer},
		CredentialConfigurationsSupported: supported,
	}
}

// Private -----------------------------------------------------------------------------------------------------------

// supportedCryptographicBindingMethods, supportedCredentialSigningAlgValues,
// and supportedProofTypes describe this issuer's actual, fixed signing and
// proof-of-possession capabilities — every credential configuration shares
// them, since there's only one signer (Vault Transit, ES256) and one proof
// scheme (an ES256-signed JWT proof) behind all of them.
var (
	supportedCryptographicBindingMethods = []string{"jwk"}
	supportedCredentialSigningAlgValues  = []string{"ES256"}
	supportedProofTypes                  = map[string]ProofTypeSupported{
		"jwt": {ProofSigningAlgValuesSupported: []string{"ES256"}},
	}
)

// claimsMetadataFor builds cc's credential_metadata.claims, nesting each
// claim's path under "credentialSubject" for a jwt_vc_json credential, flat
// for an SD-JWT VC.
func claimsMetadataFor(cc CredentialConfig) []ClaimMetadata {
	claims := make([]ClaimMetadata, len(cc.Claims))
	for i, name := range cc.Claims {
		path := []string{name}
		if cc.Format == "jwt_vc_json" {
			path = []string{"credentialSubject", name}
		}
		claims[i] = ClaimMetadata{Path: path}
	}
	return claims
}

// newCredentialConfigurationSupported builds cc's
// credential_configurations_supported entry, granted by scope.
func newCredentialConfigurationSupported(cc CredentialConfig, scope string) CredentialConfigurationSupported {
	supported := CredentialConfigurationSupported{
		Format:                               cc.Format,
		Scope:                                scope,
		CryptographicBindingMethodsSupported: supportedCryptographicBindingMethods,
		CredentialSigningAlgValuesSupported:  supportedCredentialSigningAlgValues,
		ProofTypesSupported:                  supportedProofTypes,
	}

	if len(cc.Claims) > 0 {
		supported.CredentialMetadata = &CredentialMetadataSupported{Claims: claimsMetadataFor(cc)}
	}

	switch cc.Format {
	case "jwt_vc_json":
		supported.CredentialDefinition = &CredentialDefinition{Type: []string{"VerifiableCredential", cc.Vct}}
	default:
		supported.Vct = cc.Vct
	}

	return supported
}
