package oid4vci

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"sync"
	"time"

	"github.com/tdiesler/nessus-oid4vc-go/pkg/vault"
)

// Session ===============================================================================================================

// Session is what an issued authorization code or access token resolves
// back to: the real Vault token obtained from the holder's userpass login,
// plus the client/redirect_uri context needed to validate a later token
// request against the request that originally produced this Session.
type Session struct {
	Subject     string
	VaultToken  *vault.AccessToken
	ClientId    string
	RedirectUri string
	ExpiresAt   time.Time
}

// NewSession constructs a Session that expires after ttl.
func NewSession(subject string, vaultToken *vault.AccessToken, clientId, redirectUri string, ttl time.Duration) *Session {
	return &Session{
		Subject:     subject,
		VaultToken:  vaultToken,
		ClientId:    clientId,
		RedirectUri: redirectUri,
		ExpiresAt:   time.Now().Add(ttl),
	}
}

// Expired reports whether s is past its ExpiresAt.
func (s *Session) Expired() bool {
	return time.Now().After(s.ExpiresAt)
}

// SessionStore ===================================================================================================================

// SessionStore holds this authorization server's short-lived, in-memory state:
// issued authorization codes (single-use) and issued access tokens, each
// mapping back to a Session. Purely in-process — restarting the service
// invalidates every outstanding code/token, which is acceptable for this
// POC.
type SessionStore struct {
	mu     sync.Mutex
	codes  map[string]*Session
	tokens map[string]*Session
}

// NewSessionStore constructs an empty SessionStore.
func NewSessionStore() *SessionStore {
	return &SessionStore{
		codes:  map[string]*Session{},
		tokens: map[string]*Session{},
	}
}

// IssueAccessToken stores session under a fresh, random access token and
// returns it. Unlike an authorization code, an access token is read many
// times (once per resource request), not single-use.
func (s *SessionStore) IssueAccessToken(session *Session) (string, error) {
	token, err := randomToken()
	if err != nil {
		return "", err
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	s.tokens[token] = session
	return token, nil
}

// IssueCode stores session under a fresh, random authorization code and
// returns it.
func (s *SessionStore) IssueCode(session *Session) (string, error) {
	code, err := randomToken()
	if err != nil {
		return "", err
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	s.codes[code] = session
	return code, nil
}

// RedeemCode looks up and deletes code's Session — single-use, as an
// authorization code must be (RFC 6749 §4.1.2).
func (s *SessionStore) RedeemCode(code string) (*Session, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	session, ok := s.codes[code]
	delete(s.codes, code)
	if !ok || session.Expired() {
		return nil, fmt.Errorf("invalid or expired authorization code")
	}
	return session, nil
}

// Session looks up accessToken's Session without consuming it.
func (s *SessionStore) Session(accessToken string) (*Session, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	session, ok := s.tokens[accessToken]
	if !ok || session.Expired() {
		return nil, fmt.Errorf("invalid or expired access token")
	}
	return session, nil
}

// Functions ---------------------------------------------------------------------------------------------------------

// randomToken returns a fresh, URL-safe random token suitable for use as an
// authorization code or access token.
func randomToken() (string, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("generate random token: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}
