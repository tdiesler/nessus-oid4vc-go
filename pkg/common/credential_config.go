package common

// CredentialConfig ============================================================================================================

// CredentialConfig is one statically declared credential configuration this
// issuer can produce: the format and verifiable credential type a holder
// receives under its Id.
type CredentialConfig struct {
	Id     string
	Format string
	Vct    string
}

// ScopeConfig ==================================================================================================================

// ScopeConfig is an OAuth scope and the credential_configuration_ids it
// grants — an N:M mapping between scopes and CredentialConfig entries.
type ScopeConfig struct {
	Name                       string
	CredentialConfigurationIds []string
}
