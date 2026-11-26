package oid4vci

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	co "github.com/tdiesler/nessus-oid4vc-go/pkg/common"
	"github.com/tdiesler/nessus-oid4vc-go/pkg/sdjwt"
	"github.com/tdiesler/nessus-oid4vc-go/pkg/vault"
)

// Default lifetimes for issued authorization codes, access tokens, and
// Credential Endpoint nonces.
const (
	codeTTL  = 1 * time.Minute
	tokenTTL = 5 * time.Minute
	nonceTTL = 1 * time.Minute
)

// keyProofType is the typ header OID4VCI requires on a holder's key-proof
// JWT (§8.2.1.1).
const keyProofType = "openid4vci-proof+jwt"

// CredentialIssuer =======================================================================================================

// CredentialIssuer is this service's own OID4VCI Credential Issuer,
// fronting Vault: it owns client registration and the Authorization Code
// flow's code/token lifecycle (its OAuth 2.0 Authorization Server role),
// authorizes and serves claims for /userinfo and the Credential Endpoint,
// delegates authentication (Vault's userpass auth method) and claims
// (Vault's KV v2 engine) to Vault underneath, and signs id_tokens itself
// via signer. See issue #17 for why — Vault's own OIDC provider issues a
// capability-less token usable only at its own /userinfo.
type CredentialIssuer struct {
	Issuer     string
	BaseURL    string
	cfg        *co.AppConfig
	clients    map[string]*Client
	sessions   *SessionStore
	nonces     *NonceStore
	signer     *TransitSigner
	listener   net.Listener
	httpServer *http.Server
}

// NewCredentialIssuer constructs a CredentialIssuer for issuer (this
// service's externally-visible identity — used as the id_token's "iss"
// claim and to build the discovery document's endpoint URLs), bound to addr.
func NewCredentialIssuer(baseUrl string) (*CredentialIssuer, error) {

	cfg, err := co.GetAppConfig()
	if err != nil {
		return nil, err
	}

	// This server's one registered client. cfg.OidcClient is just this
	// service's own config value — unlike pkg/oauth (which drives Vault's
	// own OIDC provider and so needs Vault's generated client_id), this
	// server's client registry is entirely its own, so there's nothing to
	// resolve from Vault. It's a public client: the caller is a holder
	// holder, which can't be expected to hold a secret.
	clients := map[string]*Client{
		cfg.OidcClient: NewClient(cfg.OidcClient, cfg.RedirectUri),
	}

	// Sign id_tokens via Vault transit.
	signer, err := NewTransitSigner("oid4vc-issuer")
	if err != nil {
		return nil, err
	}

	// Bind the address Start will serve on.
	aux, err := url.Parse(baseUrl)
	if err != nil {
		return nil, err
	}
	listener, err := net.Listen("tcp", aux.Host)
	if err != nil {
		return nil, err
	}

	return &CredentialIssuer{
		Issuer:   baseUrl,
		BaseURL:  baseUrl,
		cfg:      cfg,
		clients:  clients,
		sessions: NewSessionStore(),
		nonces:   NewNonceStore(),
		listener: listener,
		signer:   signer,
	}, nil
}

// NewCredentialIssuerFromConfig constructs a CredentialIssuer using
// this project's own AppConfig: cfg.Oid4vciAddr as both its issuer
// identity and its bind address.
func NewCredentialIssuerFromConfig() (*CredentialIssuer, error) {
	cfg, err := co.GetAppConfig()
	if err != nil {
		return nil, err
	}
	return NewCredentialIssuer(cfg.Oid4vciAddr)
}

func (ci *CredentialIssuer) WithIssuer(issuer string) *CredentialIssuer {
	ci.Issuer = issuer
	return ci
}

// Start begins serving on this server's bound listener in the background,
// returning immediately — the thing a Kubernetes container's entrypoint
// would call before blocking on its own signal handling.
func (ci *CredentialIssuer) Start() error {
	ci.httpServer = &http.Server{Handler: NewMux(ci)}
	go func() { _ = ci.httpServer.Serve(ci.listener) }()
	return nil
}

// Shutdown gracefully stops a running server started by Start. Calling it
// without a prior Start, or more than once, is a no-op.
func (ci *CredentialIssuer) Shutdown() error {
	if ci.httpServer == nil {
		return nil
	}
	httpServer := ci.httpServer
	ci.httpServer = nil
	return httpServer.Shutdown(context.Background())
}

// AuthorizedCredentialConfigurationId resolves accessToken back to its
// Session and looks up which credential_configuration_id
// credentialIdentifier belongs to, among the authorization_details that
// access token was actually granted at token exchange — the Credential
// Endpoint's authorization barrier: a holder may only request a
// credential_identifier its own access token was granted.
func (ci *CredentialIssuer) AuthorizedCredentialConfigurationId(accessToken, credentialIdentifier string) (string, error) {
	session, err := ci.sessions.Session(accessToken)
	if err != nil {
		return "", err
	}

	for _, detail := range session.AuthorizationDetails {
		for _, id := range detail.CredentialIdentifiers {
			if id == credentialIdentifier {
				return detail.CredentialConfigurationId, nil
			}
		}
	}
	return "", fmt.Errorf("access token is not authorized for credential identifier %q", credentialIdentifier)
}

// CompleteLogin authenticates username/password against Vault's userpass
// auth method on the holder's behalf, and mints a single-use authorization
// code bound to the resulting Vault token and scope.
func (ci *CredentialIssuer) CompleteLogin(clientId, redirectUri, scope, username, password string) (string, error) {
	if _, err := ci.assertClient(clientId, redirectUri); err != nil {
		return "", err
	}

	vaultToken, err := vault.UserpassLogin(username, password)
	if err != nil {
		return "", fmt.Errorf("login %q: %w", username, err)
	}

	session := NewSession(username, vaultToken, clientId, redirectUri, scope, codeTTL)
	return ci.sessions.IssueCode(session)
}

// ExchangeCode redeems code for an access token and a signed id_token,
// binding the exchange to the same client and redirect_uri the code was
// issued for (RFC 6749 §4.1.3). Clients registered here are public (RFC
// 6749 §2.3), so this doesn't authenticate the caller beyond clientId. The
// response's authorization_details (OID4VCI §6.2) are derived from the
// scope the authorization code was issued for, not re-requested here — RFC
// 9396 marks authorization_details OPTIONAL in the token response when the
// credential was requested via scope, but we return it anyway so the
// holder learns every credential_configuration_id its scope granted,
// rather than just the one it already knows.
func (ci *CredentialIssuer) ExchangeCode(code, clientId, redirectUri string) (*TokenResponse, error) {
	_, err := ci.assertClient(clientId, redirectUri)
	if err != nil {
		return nil, err
	}

	session, err := ci.sessions.RedeemCode(code)
	if err != nil {
		return nil, err
	}
	if session.ClientId != clientId || session.RedirectUri != redirectUri {
		return nil, fmt.Errorf("authorization code was not issued for this client/redirect_uri")
	}

	authorizationDetails := NewAuthorizationDetails(ci.cfg.CredentialConfigurationIdsForScope(session.Scope))

	accessSession := NewSession(session.Subject, session.VaultToken, clientId, redirectUri, session.Scope, tokenTTL).
		WithAuthorizationDetails(authorizationDetails)
	accessToken, err := ci.sessions.IssueAccessToken(accessSession)
	if err != nil {
		return nil, err
	}

	idToken, err := ci.signIdToken(session.Subject, clientId)
	if err != nil {
		return nil, err
	}

	return NewTokenResponse(accessToken, idToken, tokenTTL, authorizationDetails), nil
}

// IssueCredential is the Credential Endpoint's core logic: it resolves
// credentialIdentifier to a credential_configuration_id the access token
// was actually granted (AuthorizedCredentialConfigurationId), verifies
// proofJwt proves possession of a holder key (VerifyKeyProof), and builds
// an SD-JWT VC binding that key, naming the configuration's declared
// claims, sourced from the holder's own Vault KV data. Only the dc+sd-jwt
// format is supported.
func (ci *CredentialIssuer) IssueCredential(accessToken, credentialIdentifier, proofJwt string) (string, error) {
	session, err := ci.sessions.Session(accessToken)
	if err != nil {
		return "", err
	}

	configId, err := ci.AuthorizedCredentialConfigurationId(accessToken, credentialIdentifier)
	if err != nil {
		return "", err
	}
	config, ok := ci.cfg.CredentialConfigurationById(configId)
	if !ok {
		return "", fmt.Errorf("credential configuration %q not found", configId)
	}
	if config.Format != "dc+sd-jwt" {
		return "", fmt.Errorf("credential format %q is not supported at this endpoint", config.Format)
	}

	holderKey, err := ci.VerifyKeyProof(session.ClientId, proofJwt)
	if err != nil {
		return "", err
	}

	subjectClaims, err := ci.ReadSubjectsKeyValueClaims(accessToken)
	if err != nil {
		return "", err
	}

	builder, err := sdjwt.NewBuilder(config.Vct, jose.SigningKey{Algorithm: jose.ES256, Key: ci.signer})
	if err != nil {
		return "", err
	}
	builder.WithIssuer(ci.Issuer).WithSubject(session.Subject).WithHolderBinding(*holderKey)
	for _, name := range config.Claims {
		value, ok := subjectClaims[name]
		if !ok {
			return "", fmt.Errorf("claim %q declared for %q not found for subject %q", name, configId, session.Subject)
		}
		builder.WithDisclosableClaim(name, value)
	}

	return builder.Build()
}

// IssueNonce mints a fresh, single-use c_nonce (OID4VCI's Nonce Endpoint),
// required to bind a holder's next key-proof JWT to this specific request.
func (ci *CredentialIssuer) IssueNonce() (string, error) {
	return ci.nonces.Issue()
}

// Logout revokes accessToken's underlying Vault token and removes its
// session, ending the holder's Vault-side session immediately rather than
// letting it linger until the access token's natural expiry.
func (ci *CredentialIssuer) Logout(accessToken string) error {
	session, err := ci.sessions.RevokeAccessToken(accessToken)
	if err != nil {
		return err
	}
	return vault.RevokeToken(session.VaultToken.Token)
}

// ReadKeyValueClaims resolves accessToken back to the Vault token it was
// issued alongside, and reads alias's data from path (e.g.
// vault.SecretsPathOffers) in Vault KV — accessToken's holder needs read
// access to that path (ordinarily their own, via the subject-self policy;
// see WriteKeyValueClaims for the cross-entity write side).
func (ci *CredentialIssuer) ReadKeyValueClaims(accessToken, path, alias string) (map[string]any, error) {
	session, err := ci.sessions.Session(accessToken)
	if err != nil {
		return nil, err
	}
	return vault.NewKeyValueAccessor().ReadKeyValueClaims(session.VaultToken, path, alias)
}

// ReadSubjectsEntityClaims resolves accessToken back to the Vault token it
// was issued alongside, and reads the holder's own Identity entity
// properties — Vault's Identity-system data, as opposed to
// ReadSubjectsKeyValueClaims' KV-sourced data.
func (ci *CredentialIssuer) ReadSubjectsEntityClaims(accessToken string) (*vault.Entity, error) {
	session, err := ci.sessions.Session(accessToken)
	if err != nil {
		return nil, err
	}
	return vault.NewEntityAccessor().Entity(session.VaultToken, session.Subject)
}

// ReadSubjectsKeyValueClaims resolves accessToken back to the Vault token it
// was issued alongside, and reads the holder's own claims straight from
// Vault KV.
func (ci *CredentialIssuer) ReadSubjectsKeyValueClaims(accessToken string) (map[string]any, error) {
	session, err := ci.sessions.Session(accessToken)
	if err != nil {
		return nil, err
	}
	return vault.NewKeyValueAccessor().ReadSubjectsKeyValueClaims(session.VaultToken, session.Subject)
}

// ValidateAuthorizationRequest rejects an /authorize request up front —
// before a login form is ever shown — when its response_type isn't
// supported or its client_id/redirect_uri don't match a registered client,
// so we never redirect to an uncontrolled URI.
func (ci *CredentialIssuer) ValidateAuthorizationRequest(clientId, redirectUri, responseType string) error {
	if responseType != "code" {
		return fmt.Errorf("unsupported response_type %q", responseType)
	}
	_, err := ci.assertClient(clientId, redirectUri)
	return err
}

// VerifyKeyProof verifies proofJwt — a holder's self-signed OID4VCI
// key-proof JWT (§8.2.1.1), embedding its own public key in its header —
// was issued by clientId for ci's issuer identity, and consumes the nonce
// it names (single-use, anti-replay). Returns the public key the holder
// proved possession of, for binding into the resulting credential's "cnf"
// claim.
func (ci *CredentialIssuer) VerifyKeyProof(clientId, proofJwt string) (*jose.JSONWebKey, error) {
	token, err := jwt.ParseSigned(proofJwt, []jose.SignatureAlgorithm{jose.ES256})
	if err != nil {
		return nil, fmt.Errorf("parse key proof: %w", err)
	}
	if len(token.Headers) != 1 || token.Headers[0].JSONWebKey == nil {
		return nil, fmt.Errorf("key proof: missing embedded jwk")
	}
	if token.Headers[0].ExtraHeaders[jose.HeaderType] != keyProofType {
		return nil, fmt.Errorf("key proof: unexpected typ %q", token.Headers[0].ExtraHeaders[jose.HeaderType])
	}
	holderKey := token.Headers[0].JSONWebKey

	var claims jwt.Claims
	var custom struct {
		Nonce string `json:"nonce"`
	}
	if err := token.Claims(holderKey.Key, &claims, &custom); err != nil {
		return nil, fmt.Errorf("verify key proof: %w", err)
	}
	if err := claims.Validate(jwt.Expected{Issuer: clientId, AnyAudience: jwt.Audience{ci.Issuer}, Time: time.Now()}); err != nil {
		return nil, fmt.Errorf("verify key proof: %w", err)
	}
	if err := ci.nonces.Consume(custom.Nonce); err != nil {
		return nil, fmt.Errorf("verify key proof: %w", err)
	}

	return holderKey, nil
}

// WriteKeyValueClaims resolves accessToken back to the Vault token it was
// issued alongside, and writes data to alias's path — accessToken's holder
// needs write access to that path (e.g. an issuer's per-subject
// subject-{path}-write-{alias} policy), not read access to it. This is the
// delegated, cross-entity half of the mechanism ReadKeyValueClaims reads
// back from.
func (ci *CredentialIssuer) WriteKeyValueClaims(accessToken, path, alias string, data map[string]any) error {
	session, err := ci.sessions.Session(accessToken)
	if err != nil {
		return err
	}
	return vault.NewKeyValueAccessor().WriteKeyValueClaims(session.VaultToken, path, alias, data)
}

// Client ===============================================================================================================

// Client is a public OAuth 2.0 client registered with this authorization
// server (RFC 6749 §2.1) — the role a holder wallet plays, which can't be
// expected to hold a secret. This is this service's own client registry,
// distinct from Vault's identity/oidc/client: fronting Vault means client
// registration becomes this service's concern too, not Vault's. Compare
// OAuthClient, the client side of the same protocol.
type Client struct {
	Id          string
	RedirectUri string
}

// NewClient constructs a Client.
func NewClient(id, redirectUri string) *Client {
	return &Client{
		Id:          id,
		RedirectUri: redirectUri,
	}
}

// Private -------------------------------------------------------------------------------------------------------------

// assertClient resolves clientId and checks redirectUri against its registration.
func (ci *CredentialIssuer) assertClient(clientId, redirectUri string) (*Client, error) {
	client, ok := ci.clients[clientId]
	if !ok {
		return nil, fmt.Errorf("unknown client %q", clientId)
	}
	if client.RedirectUri != redirectUri {
		return nil, fmt.Errorf("redirect_uri does not match client %q's registration", clientId)
	}
	return client, nil
}

// signIdToken builds and signs a minimal OIDC id_token for subject,
// audienced to clientId.
func (ci *CredentialIssuer) signIdToken(subject, clientId string) (string, error) {
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: ci.signer}, &jose.SignerOptions{})
	if err != nil {
		return "", fmt.Errorf("build id_token signer: %w", err)
	}

	now := time.Now()
	claims := jwt.Claims{
		Issuer:   ci.Issuer,
		Subject:  subject,
		Audience: jwt.Audience{clientId},
		IssuedAt: jwt.NewNumericDate(now),
		Expiry:   jwt.NewNumericDate(now.Add(tokenTTL)),
	}

	idToken, err := jwt.Signed(signer).Claims(claims).Serialize()
	if err != nil {
		return "", fmt.Errorf("sign id_token: %w", err)
	}
	return idToken, nil
}

// TokenResponse ==============================================================================================================

// TokenResponse is an OAuth 2.0 / OIDC Access Token Response (RFC 6749
// §4.1.4, OIDC Core 1.0 §3.1.3.3), returned by this server's token
// endpoint, extended with OID4VCI's authorization_details (§6.2) naming
// the credential(s) the holder is now entitled to request.
type TokenResponse struct {
	AccessToken          string                `json:"access_token"`
	TokenType            string                `json:"token_type"`
	IdToken              string                `json:"id_token"`
	ExpiresIn            int                   `json:"expires_in"`
	AuthorizationDetails []AuthorizationDetail `json:"authorization_details,omitempty"`
}

// NewTokenResponse constructs a TokenResponse valid for ttl.
func NewTokenResponse(accessToken, idToken string, ttl time.Duration, authorizationDetails []AuthorizationDetail) *TokenResponse {
	return &TokenResponse{
		AccessToken:          accessToken,
		TokenType:            "Bearer",
		IdToken:              idToken,
		ExpiresIn:            int(ttl.Seconds()),
		AuthorizationDetails: authorizationDetails,
	}
}

// AuthorizationDetail ========================================================================================================

// AuthorizationDetail is one entry of a Token Response's
// authorization_details array (RFC 9396, OID4VCI §6.2, type
// "openid_credential"): a credential_configuration_id the holder's scope
// granted, and the credential_identifiers it must use to request that
// credential at the Credential Endpoint.
type AuthorizationDetail struct {
	Type                      string   `json:"type"`
	CredentialConfigurationId string   `json:"credential_configuration_id"`
	CredentialIdentifiers     []string `json:"credential_identifiers"`
}

// NewAuthorizationDetails builds one AuthorizationDetail per credential
// configuration id, each with a single credential_identifier derived by
// appending "_0000" to the configuration id — this service's one Vault
// Identity entity per credential subject (see AGENTS.md) means there's
// exactly one Credential Dataset per configuration per subject, so a fixed
// suffix is enough to name it.
func NewAuthorizationDetails(credentialConfigurationIds []string) []AuthorizationDetail {
	details := make([]AuthorizationDetail, len(credentialConfigurationIds))
	for i, id := range credentialConfigurationIds {
		details[i] = AuthorizationDetail{
			Type:                      "openid_credential",
			CredentialConfigurationId: id,
			CredentialIdentifiers:     []string{id + "_0000"},
		}
	}
	return details
}
