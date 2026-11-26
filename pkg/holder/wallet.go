package holder

import (
	"fmt"
	"time"

	co "github.com/tdiesler/nessus-oid4vc-go/pkg/common"
)

// Holder =================================================================================================================

// Wallet is the holder's handle on one issuer's user — resolved from
// WalletState at load time, alias falling back to the holder's default
// issuer and username falling back to the issuer's default user — used to
// drive and persist every CLI operation against that issuer and user.
type Wallet struct {
	state    *WalletState
	issuer   *Issuer
	username string
}

// NewWallet loads the holder's wallet state from its config and resolves the target issuer and username.
func NewWallet(iss, username string) (*Wallet, error) {

	state, err := LoadWalletState()
	if err != nil {
		return nil, err
	}

	issuer, err := resolveIssuer(state, iss)
	if err != nil {
		return nil, err
	}

	if username == "" {
		username = issuer.DefaultUser
	}
	if username == "" {
		return nil, fmt.Errorf("no user specified and issuer %q has no default user", issuer.Alias)
	}

	return &Wallet{state: state, issuer: issuer, username: username}, nil
}

// CreateKey generates an ES256 holder key for h's user against h's issuer,
// named name if given, or auto-derived otherwise. Returns the key's ID.
func (w *Wallet) CreateKey(name string) (string, error) {
	conn := w.connectionOrNew()

	kid, err := conn.AddHolderKey(name)
	if err != nil {
		return "", err
	}

	if err = w.Save(); err != nil {
		return "", err
	}
	return kid, nil
}

// GetCredential fetches a credential for h's user from h's issuer, naming
// it by credentialIdentifier (from authorization_details captured at
// login), proving possession of the holder key named key — or h's user's
// default key. Refreshes the session's token first if it's near expiry and
// a refresh token is available, failing clearly instead if not. Stores and
// returns the issued credential.
func (w *Wallet) GetCredential(key, credentialIdentifier string) (string, error) {
	if credentialIdentifier == "" {
		return "", fmt.Errorf("either a credential identifier is required")
	}

	conn, ok := w.issuer.Users[w.username]
	if !ok || conn.Token == nil {
		iss := w.issuer.Alias
		return "", fmt.Errorf("no active session for %q with issuer %q; run login first", w.username, iss)
	}

	holderKey, err := conn.HolderKey(key)
	if err != nil {
		return "", err
	}

	if conn.Token.ExpiresWithin(30 * time.Second) {
		if conn.Token.RefreshToken == "" {
			return "", fmt.Errorf("access token expired; run 'oid4vc login' again")
		}
		if err := w.refreshSession(conn); err != nil {
			return "", err
		}
	}

	metadata, err := discoverCredentialIssuerMetadata(w.issuer.IssuerURL)
	if err != nil {
		return "", err
	}

	cNonce, err := fetchNonce(metadata.NonceEndpoint, conn.Token.AccessToken)
	if err != nil {
		return "", err
	}

	vc, err := fetchCredential(metadata.CredentialEndpoint, conn.Token.AccessToken, conn.ClientId, w.issuer.IssuerURL, credentialIdentifier, holderKey, cNonce)
	if err != nil {
		return "", err
	}

	conn.SetCredential(credentialIdentifier, vc)
	if err = w.Save(); err != nil {
		return "", err
	}

	return vc, nil
}

// Issuer returns the Issuer h was resolved against.
func (w *Wallet) Issuer() *Issuer {
	return w.issuer
}

// Login authenticates h's user against h's issuer via the Authorization
// Code grant — browser-driven, either headlessly with password or
// interactively via the system browser — at clientId, defaulting to the
// issuer's default client, storing the resulting session in the holder.
func (w *Wallet) Login(clientId, scope string, browser bool, password string) error {
	iss := w.issuer.Alias
	if w.issuer.RedirectUri == "" {
		return fmt.Errorf("issuer %q has no redirectUri configured", iss)
	}
	if clientId == "" {
		clientId = w.issuer.DefaultClient
	}
	if clientId == "" {
		return fmt.Errorf("no client specified and issuer %q has no default client", iss)
	}

	metadata, err := discoverMetadata(w.issuer.IssuerURL)
	if err != nil {
		return err
	}

	browserLogin := NewBrowserLogin(metadata.AuthorizationEndpoint, clientId, w.issuer.RedirectUri, scope)
	var code string
	if browser {
		code, err = browserLogin.Interactive()
	} else {
		code, err = browserLogin.Headless(w.username, password)
	}
	if err != nil {
		return err
	}

	token, authDetails, err := exchangeAuthorizationCode(metadata.TokenEndpoint, clientId, code, w.issuer.RedirectUri)
	if err != nil {
		return err
	}

	conn, ok := w.issuer.Users[w.username]
	if !ok {
		conn = NewConnection(clientId)
		w.issuer.Users[w.username] = conn
	}
	conn.WithToken(token)
	conn.AuthorizationDetails = authDetails
	w.issuer.DefaultUser = w.username

	return w.Save()
}

// Logout ends h's user's session against h's issuer. Reports whether a
// session actually existed to end.
func (w *Wallet) Logout() (bool, error) {
	conn, ok := w.issuer.Users[w.username]
	if !ok || conn.Token == nil {
		return false, nil
	}

	metadata, err := discoverMetadata(w.issuer.IssuerURL)
	if err != nil {
		return false, err
	}
	switch {
	case metadata.EndSessionEndpoint != "":
		err = endSession(metadata.EndSessionEndpoint, conn.ClientId, conn.Token)
	case metadata.RevocationEndpoint != "":
		err = revokeToken(metadata.RevocationEndpoint, conn.ClientId, conn.Token.AccessToken)
	}
	if err != nil {
		return false, err
	}

	conn.Token = nil
	if err := w.Save(); err != nil {
		return false, err
	}
	return true, nil
}

// Save persists h's issuer back to the holder.
func (w *Wallet) Save() error {
	return w.state.SaveWalletState(w.issuer.Alias)
}

// Username returns the username h was resolved against.
func (w *Wallet) Username() string {
	return w.username
}

// Private -----------------------------------------------------------------------------------------------------------

// connectionOrNew returns h's user's Connection, creating and registering
// one against h's issuer's default client if none exists yet.
func (w *Wallet) connectionOrNew() *Connection {
	conn, ok := w.issuer.Users[w.username]
	if !ok {
		conn = NewConnection(w.issuer.DefaultClient)
		w.issuer.Users[w.username] = conn
	}
	return conn
}

// refreshSession redeems a connection's refresh token for a new one and persists
// the result.
func (w *Wallet) refreshSession(con *Connection) error {
	metadata, err := discoverMetadata(w.issuer.IssuerURL)
	if err != nil {
		return err
	}
	refreshed, authDetails, err := refreshToken(metadata.TokenEndpoint, con.ClientId, con.Token)
	if err != nil {
		return fmt.Errorf("refresh token: %w", err)
	}
	con.WithToken(refreshed)
	con.AuthorizationDetails = authDetails
	return w.Save()
}

// Functions ---------------------------------------------------------------------------------------------------------

// CredentialIssuerMetadata fetches issuerAlias's OID4VCI credential issuer
// metadata document, falling back to the holder's default issuer. Unlike
// Wallet's other operations, this is read-only and user-independent, so it
// doesn't go through NewWallet.
func CredentialIssuerMetadata(issuerAlias string) (*co.CredentialIssuerMetadata, error) {
	state, err := LoadWalletState()
	if err != nil {
		return nil, err
	}

	issuer, err := resolveIssuer(state, issuerAlias)
	if err != nil {
		return nil, err
	}

	return discoverCredentialIssuerMetadata(issuer.IssuerURL)
}

// CurrentState resolves issuerAlias to a configured issuer, falling back to
// the holder's default issuer, and returns its alias and default user.
func CurrentState(issuerAlias string) (alias, username string, err error) {
	state, err := LoadWalletState()
	if err != nil {
		return "", "", err
	}

	issuer, err := resolveIssuer(state, issuerAlias)
	if err != nil {
		return "", "", err
	}

	return issuer.Alias, issuer.DefaultUser, nil
}

// OpenIDConfiguration fetches issuerAlias's OpenID Connect discovery
// document, falling back to the holder's default issuer. Unlike Wallet's
// other operations, this is read-only and user-independent, so it doesn't
// go through NewWallet.
func OpenIDConfiguration(issuerAlias string) (*co.AuthorizationServerMetadata, error) {
	state, err := LoadWalletState()
	if err != nil {
		return nil, err
	}

	issuer, err := resolveIssuer(state, issuerAlias)
	if err != nil {
		return nil, err
	}

	return discoverMetadata(issuer.IssuerURL)
}

// OtherIssuer resolves the holder's one other configured issuer — the one
// that isn't currently the default — requiring exactly two issuers to be
// configured, since with any other count there's no single unambiguous
// "other" to switch to.
func OtherIssuer() (string, error) {
	state, err := LoadWalletState()
	if err != nil {
		return "", err
	}
	if state.DefaultIssuer == "" {
		return "", fmt.Errorf("no default issuer configured")
	}
	if len(state.Issuers) != 2 {
		return "", fmt.Errorf("switch issuer: requires exactly 2 configured issuers, found %d", len(state.Issuers))
	}
	for alias := range state.Issuers {
		if alias != state.DefaultIssuer {
			return alias, nil
		}
	}
	return "", fmt.Errorf("no other issuer configured")
}

// resolveIssuer looks up alias in state's configured issuers, falling back
// to state's default issuer when alias is empty.
func resolveIssuer(state *WalletState, alias string) (*Issuer, error) {
	if alias == "" {
		alias = state.DefaultIssuer
	}
	if alias == "" {
		return nil, fmt.Errorf("no issuer specified and no default issuer configured")
	}
	issuer, ok := state.Issuers[alias]
	if !ok {
		return nil, fmt.Errorf("no issuer %q configured", alias)
	}
	return issuer, nil
}

// SwitchIssuer makes alias the holder's new default issuer, persisting the
// change to both alias's file and, if it differs, the previous default
// issuer's file — each file's own Default flag is what LoadWalletState
// derives WalletState.DefaultIssuer from.
func SwitchIssuer(alias string) error {
	state, err := LoadWalletState()
	if err != nil {
		return err
	}

	if _, ok := state.Issuers[alias]; !ok {
		return fmt.Errorf("no issuer %q configured", alias)
	}

	previous := state.DefaultIssuer
	state.DefaultIssuer = alias

	if previous != "" && previous != alias {
		if err := state.SaveWalletState(previous); err != nil {
			return err
		}
	}
	return state.SaveWalletState(alias)
}
