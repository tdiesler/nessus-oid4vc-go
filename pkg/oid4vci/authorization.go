package oid4vci

import (
	"context"
	"fmt"
	"net"
	"net/url"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	co "github.com/tdiesler/nessus-oid4vc-go/pkg/common"
	"github.com/tdiesler/nessus-oid4vc-go/pkg/vault"
)

// Default lifetimes for issued authorization codes and access tokens.
const (
	codeTTL  = 1 * time.Minute
	tokenTTL = 5 * time.Minute
)

// AuthorizationServer =======================================================================================================

// AuthorizationServer is this service's own OAuth 2.0 Authorization Server,
// fronting Vault: it owns client registration and the Authorization Code
// flow's code/token lifecycle, delegates authentication (Vault's userpass
// auth method) and claims (Vault's KV v2 engine) to Vault underneath, and
// signs id_tokens itself via signer. See issue #17 for why — Vault's own
// OIDC provider issues a capability-less token usable only at its own
// /userinfo.
// [TODO >>>] This is also an OID4VCI Server
type AuthorizationServer struct {
	Issuer   string
	BaseURL  string
	cfg      *co.AppConfig
	clients  map[string]*Client
	sessions *SessionStore
	signer   *TransitSigner
	listener net.Listener
	server   *Server
}

// NewAuthorizationServer constructs an AuthorizationServer for issuer (this
// service's externally-visible identity — used as the id_token's "iss"
// claim and to build the discovery document's endpoint URLs), bound to addr.
func NewAuthorizationServer(baseUrl string) (*AuthorizationServer, error) {

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

	return &AuthorizationServer{
		Issuer:   baseUrl,
		BaseURL:  baseUrl,
		cfg:      cfg,
		clients:  clients,
		sessions: NewSessionStore(),
		listener: listener,
		signer:   signer,
	}, nil
}

// NewAuthorizationServerFromConfig constructs an AuthorizationServer using
// this project's own AppConfig: cfg.Oid4vciAddr as both its issuer
// identity and its bind address.
func NewAuthorizationServerFromConfig() (*AuthorizationServer, error) {
	cfg, err := co.GetAppConfig()
	if err != nil {
		return nil, err
	}
	return NewAuthorizationServer(cfg.Oid4vciAddr)
}

func (as *AuthorizationServer) WithIssuer(issuer string) *AuthorizationServer {
	as.Issuer = issuer
	return as
}

// Start begins serving on this server's bound listener in the background,
// returning immediately — the thing a Kubernetes container's entrypoint
// would call before blocking on its own signal handling.
func (as *AuthorizationServer) Start() error {
	as.server = NewServer("", as)
	go func() { _ = as.server.ServeListener(as.listener) }()
	return nil
}

// Shutdown gracefully stops a running server started by Start. Calling it
// without a prior Start, or more than once, is a no-op.
func (as *AuthorizationServer) Shutdown() error {
	if as.server == nil {
		return nil
	}
	server := as.server
	as.server = nil
	return server.Shutdown(context.Background())
}

// CompleteLogin authenticates username/password against Vault's userpass
// auth method on the holder's behalf, and mints a single-use authorization
// code bound to the resulting Vault token and scope.
func (as *AuthorizationServer) CompleteLogin(clientId, redirectUri, scope, username, password string) (string, error) {
	if _, err := as.assertClient(clientId, redirectUri); err != nil {
		return "", err
	}

	vaultToken, err := vault.UserpassLogin(username, password)
	if err != nil {
		return "", fmt.Errorf("login %q: %w", username, err)
	}

	session := NewSession(username, vaultToken, clientId, redirectUri, scope, codeTTL)
	return as.sessions.IssueCode(session)
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
func (as *AuthorizationServer) ExchangeCode(code, clientId, redirectUri string) (*TokenResponse, error) {
	_, err := as.assertClient(clientId, redirectUri)
	if err != nil {
		return nil, err
	}

	session, err := as.sessions.RedeemCode(code)
	if err != nil {
		return nil, err
	}
	if session.ClientId != clientId || session.RedirectUri != redirectUri {
		return nil, fmt.Errorf("authorization code was not issued for this client/redirect_uri")
	}

	accessToken, err := as.sessions.IssueAccessToken(NewSession(session.Subject, session.VaultToken, clientId, redirectUri, session.Scope, tokenTTL))
	if err != nil {
		return nil, err
	}

	idToken, err := as.signIdToken(session.Subject, clientId)
	if err != nil {
		return nil, err
	}

	authorizationDetails := NewAuthorizationDetails(as.cfg.CredentialConfigurationIdsForScope(session.Scope))
	return NewTokenResponse(accessToken, idToken, tokenTTL, authorizationDetails), nil
}

// Logout revokes accessToken's underlying Vault token and removes its
// session, ending the holder's Vault-side session immediately rather than
// letting it linger until the access token's natural expiry.
func (as *AuthorizationServer) Logout(accessToken string) error {
	session, err := as.sessions.RevokeAccessToken(accessToken)
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
func (as *AuthorizationServer) ReadKeyValueClaims(accessToken, path, alias string) (map[string]any, error) {
	session, err := as.sessions.Session(accessToken)
	if err != nil {
		return nil, err
	}
	return vault.NewKeyValueAccessor().ReadKeyValueClaims(session.VaultToken, path, alias)
}

// ReadSubjectsEntityClaims resolves accessToken back to the Vault token it
// was issued alongside, and reads the holder's own Identity entity
// properties — Vault's Identity-system data, as opposed to
// ReadSubjectsKeyValueClaims' KV-sourced data.
func (as *AuthorizationServer) ReadSubjectsEntityClaims(accessToken string) (*vault.Entity, error) {
	session, err := as.sessions.Session(accessToken)
	if err != nil {
		return nil, err
	}
	return vault.NewEntityAccessor().Entity(session.VaultToken, session.Subject)
}

// ReadSubjectsKeyValueClaims resolves accessToken back to the Vault token it
// was issued alongside, and reads the holder's own claims straight from
// Vault KV.
func (as *AuthorizationServer) ReadSubjectsKeyValueClaims(accessToken string) (map[string]any, error) {
	session, err := as.sessions.Session(accessToken)
	if err != nil {
		return nil, err
	}
	return vault.NewKeyValueAccessor().ReadSubjectsKeyValueClaims(session.VaultToken, session.Subject)
}

// ValidateAuthorizationRequest rejects an /authorize request up front —
// before a login form is ever shown — when its response_type isn't
// supported or its client_id/redirect_uri don't match a registered client,
// so we never redirect to an uncontrolled URI.
func (as *AuthorizationServer) ValidateAuthorizationRequest(clientId, redirectUri, responseType string) error {
	if responseType != "code" {
		return fmt.Errorf("unsupported response_type %q", responseType)
	}
	_, err := as.assertClient(clientId, redirectUri)
	return err
}

// WriteKeyValueClaims resolves accessToken back to the Vault token it was
// issued alongside, and writes data to alias's path — accessToken's holder
// needs write access to that path (e.g. an issuer's per-subject
// subject-{path}-write-{alias} policy), not read access to it. This is the
// delegated, cross-entity half of the mechanism ReadKeyValueClaims reads
// back from.
func (as *AuthorizationServer) WriteKeyValueClaims(accessToken, path, alias string, data map[string]any) error {
	session, err := as.sessions.Session(accessToken)
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
func (as *AuthorizationServer) assertClient(clientId, redirectUri string) (*Client, error) {
	client, ok := as.clients[clientId]
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
func (as *AuthorizationServer) signIdToken(subject, clientId string) (string, error) {
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: as.signer}, &jose.SignerOptions{})
	if err != nil {
		return "", fmt.Errorf("build id_token signer: %w", err)
	}

	now := time.Now()
	claims := jwt.Claims{
		Issuer:   as.Issuer,
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
