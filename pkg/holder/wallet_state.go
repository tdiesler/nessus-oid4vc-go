package holder

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jose-util/generator"
	co "github.com/tdiesler/nessus-oid4vc-go/pkg/common"
)

// Flavor values identifying which backend an Issuer authenticates against.
const (
	IssuerKeycloak = "keycloak"
	IssuerVault    = "vault"
)

// WalletState ===========================================================================================================

// WalletState is the holder holder's full picture of the issuers it knows
// about, merged from the holder directory's one-file-per-issuer
// holder.<alias>.json files (see LoadWalletStateFromDir), keyed by a short
// local alias — e.g. a Keycloak realm name, or a chosen name for a Vault
// OIDC provider — taken from each file's own name. It is never itself
// marshaled: each Issuer is (de)serialized to its own file.
type WalletState struct {
	DefaultIssuer string
	Issuers       map[string]*Issuer
}

// NewWalletState constructs an empty WalletState.
func NewWalletState() *WalletState {
	return &WalletState{
		Issuers: map[string]*Issuer{},
	}
}

// LoadWalletState loads the holder state from this project's own .config
// directory (see pkg/common.HomeDir).
func LoadWalletState() (*WalletState, error) {
	return LoadWalletStateFromDir(filepath.Join(co.HomeDir(), ".config"))
}

// LoadWalletStateFromDir reads every holder.<alias>.json file present under
// dir — each holding exactly one Issuer — and merges them into one
// WalletState keyed by the alias taken from the file name. A missing
// directory, or no matching files, yields an empty WalletState rather than
// an error — there's simply nothing configured yet. The issuer marked
// Default (there should be at most one) becomes the WalletState's
// DefaultIssuer.
func LoadWalletStateFromDir(dir string) (*WalletState, error) {
	matches, err := filepath.Glob(filepath.Join(dir, "wallet.*.json"))
	if err != nil {
		return nil, fmt.Errorf("glob %s: %w", dir, err)
	}

	merged := NewWalletState()
	for _, path := range matches {
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", path, err)
		}
		var issuer Issuer
		if err := json.Unmarshal(data, &issuer); err != nil {
			return nil, fmt.Errorf("parse %s: %w", path, err)
		}
		alias := aliasFromWalletFile(path)
		merged.Issuers[alias] = &issuer
		if issuer.Default {
			merged.DefaultIssuer = alias
		}
	}
	return merged, nil
}

// SaveWalletState persists alias's Issuer from w into dir's dedicated
// holder.<alias>.json file, leaving every other issuer's file untouched.
func (w *WalletState) SaveWalletState(alias string) error {
	return w.SaveWalletStateToDir(alias, filepath.Join(co.HomeDir(), ".config"))
}

// SaveWalletStateToDir persists alias's Issuer from w into dir's dedicated
// holder.<alias>.json file, leaving every other issuer's file untouched.
func (w *WalletState) SaveWalletStateToDir(alias string, dir string) error {
	issuer, ok := w.Issuers[alias]
	if !ok {
		return fmt.Errorf("no issuer %q in holder state", alias)
	}
	issuer.Default = alias == w.DefaultIssuer

	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create %s: %w", dir, err)
	}
	data, err := json.MarshalIndent(issuer, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal issuer %q: %w", alias, err)
	}
	path := filepath.Join(dir, fmt.Sprintf("wallet.%s.json", alias))
	if err = os.WriteFile(path, data, 0o600); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	return nil
}

// Issuer =================================================================================================================

// Issuer is one OIDC authorization server the holder can log in against: a
// Keycloak realm, or a Vault OIDC provider. IssuerURL is the full discovery
// base — IssuerURL + "/.well-known/openid-configuration" resolves its
// endpoints — so for Keycloak it already includes the realm path segment;
// no separate realm field is needed. RedirectUri is the redirect_uri a
// browser-driven login completes through; it must be one of DefaultClient's
// registered redirect URIs at this Issuer.
type Issuer struct {
	Alias         string                 `json:"alias"`
	Default       bool                   `json:"default,omitempty"`
	IssuerURL     string                 `json:"issuerUrl"`
	RedirectUri   string                 `json:"redirectUri,omitempty"`
	DefaultClient string                 `json:"defaultClient,omitempty"`
	DefaultUser   string                 `json:"defaultUser,omitempty"`
	Users         map[string]*Connection `json:"users,omitempty"`
}

// NewIssuer constructs an Issuer of kind for the authorization server at issuerURL.
func NewIssuer(alias, issuerURL string) *Issuer {
	return &Issuer{
		Alias:     alias,
		IssuerURL: issuerURL,
		Users:     map[string]*Connection{},
	}
}

// Connection =============================================================================================================

// Connection is one authenticated user's session and credential material
// within an Issuer.
type Connection struct {
	ClientId             string                `json:"clientId"`
	AuthorizationDetails []AuthorizationDetail `json:"authorizationDetails,omitempty"`
	DefaultKey           string                `json:"defaultKey,omitempty"`
	Keys                 []jose.JSONWebKey     `json:"keys,omitempty"`
	Credentials          map[string]string     `json:"credentials,omitempty"`
	Token                *Token                `json:"token,omitempty"`
}

// NewConnection constructs a Connection authenticated as clientId.
func NewConnection(clientId string) *Connection {
	return &Connection{
		ClientId:    clientId,
		Credentials: map[string]string{},
	}
}

// AddHolderKey generates a fresh ES256 holder key for c — named kid if
// given, or auto-derived as "es256#<n>" (one past the highest existing
// "es256#" suffix) otherwise — replacing any existing key with the same
// ID, and sets it as c's DefaultKey. Returns the key's ID.
func (c *Connection) AddHolderKey(kid string) (string, error) {
	const prefix = "es256#"

	if kid == "" {
		kid = nextHolderKeyID(c.Keys, prefix)
	} else {
		c.Keys = removeKeyByID(c.Keys, kid)
	}

	key, err := newHolderKey(kid)
	if err != nil {
		return "", err
	}
	c.Keys = append(c.Keys, key)
	c.DefaultKey = kid
	return kid, nil
}

// HolderKey returns c's holder key named kid — or, when kid is empty, c's
// DefaultKey, or failing that its first key — whichever is the most
// specific selection actually available.
func (c *Connection) HolderKey(kid string) (jose.JSONWebKey, error) {
	if kid == "" {
		kid = c.DefaultKey
	}
	if kid != "" {
		for _, key := range c.Keys {
			if key.KeyID == kid {
				return key, nil
			}
		}
		return jose.JSONWebKey{}, fmt.Errorf("no holder key %q", kid)
	}
	if len(c.Keys) == 0 {
		return jose.JSONWebKey{}, fmt.Errorf("no holder key")
	}
	return c.Keys[0], nil
}

// SetCredential stores credential under key, initializing Credentials if c
// was loaded from a holder file that omitted it — omitempty drops the
// "credentials" key entirely once there are none to write.
func (c *Connection) SetCredential(key, credential string) {
	if c.Credentials == nil {
		c.Credentials = map[string]string{}
	}
	c.Credentials[key] = credential
}

// WithToken sets c's Token.
func (c *Connection) WithToken(token *Token) *Connection {
	c.Token = token
	return c
}

// Token ===================================================================================================================

// Token is the OAuth 2.0 token material obtained for a Connection: the
// bearer access token used at protected endpoints, the refresh token used
// to renew it, and when the access token expires.
type Token struct {
	AccessToken  string    `json:"accessToken,omitempty"`
	RefreshToken string    `json:"refreshToken,omitempty"`
	ExpiresAt    time.Time `json:"expiresAt"`
}

// NewToken constructs a Token that expires at expiresAt.
func NewToken(accessToken, refreshToken string, expiresAt time.Time) *Token {
	return &Token{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		ExpiresAt:    expiresAt,
	}
}

// Expired reports whether t is past its ExpiresAt.
func (t *Token) Expired() bool {
	return time.Now().After(t.ExpiresAt)
}

// ExpiresWithin reports whether t's ExpiresAt is within d of now — for
// refreshing a token shortly before it actually expires, rather than
// waiting for a request to fail first.
func (t *Token) ExpiresWithin(d time.Duration) bool {
	return time.Now().Add(d).After(t.ExpiresAt)
}

// AuthorizationDetail =====================================================================================================

// AuthorizationDetail is one entry of an OAuth 2.0 Rich Authorization
// Request authorization_details array (RFC 9396), as returned by an
// OID4VCI-aware token endpoint.
type AuthorizationDetail struct {
	Type                      string   `json:"type"`
	CredentialConfigurationId string   `json:"credential_configuration_id,omitempty"`
	CredentialIdentifiers     []string `json:"credential_identifiers,omitempty"`
	IssuedCredentialId        string   `json:"issued_credential_id,omitempty"`
}

// NewAuthorizationDetail constructs an AuthorizationDetail of detailType for
// credentialConfigurationId. IssuedCredentialId is set later, once the
// token endpoint has actually issued a credential against this detail.
func NewAuthorizationDetail(detailType, credentialConfigurationId string, credentialIdentifiers []string) AuthorizationDetail {
	return AuthorizationDetail{
		Type:                      detailType,
		CredentialConfigurationId: credentialConfigurationId,
		CredentialIdentifiers:     credentialIdentifiers,
	}
}

// Functions ---------------------------------------------------------------------------------------------------------

// aliasFromWalletFile derives an issuer's alias from its holder.<alias>.json
// file name.
func aliasFromWalletFile(path string) string {
	name := filepath.Base(path)
	name = strings.TrimPrefix(name, "wallet.")
	name = strings.TrimSuffix(name, ".json")
	return name
}

// newHolderKey generates a fresh ES256 (P-256) key with the given key ID,
// via go-jose's own key generator rather than assembling the curve/key-size
// pairing by hand.
func newHolderKey(kid string) (jose.JSONWebKey, error) {
	_, privateKey, err := generator.NewSigningKey(jose.ES256, 0)
	if err != nil {
		return jose.JSONWebKey{}, fmt.Errorf("generate holder key: %w", err)
	}
	return jose.JSONWebKey{
		Key:       privateKey,
		KeyID:     kid,
		Algorithm: string(jose.ES256),
		Use:       "sig",
	}, nil
}

// nextHolderKeyID returns prefix followed by one past the highest numeric
// suffix among keys whose KeyID already starts with prefix — prefix + "1"
// when none match.
func nextHolderKeyID(keys []jose.JSONWebKey, prefix string) string {
	idx := 0
	for _, key := range keys {
		suffix, ok := strings.CutPrefix(key.KeyID, prefix)
		if !ok {
			continue
		}
		if n, err := strconv.Atoi(suffix); err == nil && n > idx {
			idx = n
		}
	}
	return fmt.Sprintf("%s%d", prefix, idx+1)
}

// removeKeyByID returns keys with any entry whose KeyID equals kid removed.
func removeKeyByID(keys []jose.JSONWebKey, kid string) []jose.JSONWebKey {
	kept := make([]jose.JSONWebKey, 0, len(keys))
	for _, key := range keys {
		if key.KeyID != kid {
			kept = append(kept, key)
		}
	}
	return kept
}
