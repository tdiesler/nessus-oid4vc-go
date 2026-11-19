package vault

import (
	"fmt"
)

// AuthorizationAccessor ===============================================================================================

// AuthorizationAccessor accesses Vault's native userpass auth method.
type AuthorizationAccessor struct {
}

// NewAuthorizationAccessor constructs an AuthorizationAccessor.
func NewAuthorizationAccessor() *AuthorizationAccessor {
	return &AuthorizationAccessor{}
}

// Login authenticates username/password against Vault's userpass auth method
// and returns the resulting AccessToken: a real Vault token, scoped by
// whatever policies are attached to username, usable directly against
// Vault's other APIs — e.g. EntityAccessor and KeyValueAccessor — with no
// OAuth/OIDC step involved.
func (s *AuthorizationAccessor) Login(username, password string) (*AccessToken, error) {
	client, err := NewClient()
	if err != nil {
		return nil, err
	}

	secret, err := client.Logical().Write("auth/userpass/login/"+username, map[string]any{
		"password": password,
	})
	if err != nil {
		return nil, fmt.Errorf("userpass login %q: %w", username, err)
	}
	if secret == nil || secret.Auth == nil {
		return nil, fmt.Errorf("userpass login %q: no auth in response", username)
	}

	token := NewAccessTokenFromAuth(secret.Auth)
	return token, nil
}

// RevokeToken revokes token at Vault's own token-revocation endpoint — the
// equivalent of a logout. A Vault token can always revoke itself, so this
// needs no privileges beyond token itself. The client must be
// authenticated as token before calling RevokeSelf: the Vault API only
// ever revokes whichever token the client itself is set to use, not an
// argument passed in.
func (s *AuthorizationAccessor) RevokeToken(token string) error {
	client, err := NewClient(token)
	if err != nil {
		return err
	}
	return client.Auth().Token().RevokeSelf(token)
}

// Functions -----------------------------------------------------------------------------------------------------------

func RevokeToken(token string) error {
	return NewAuthorizationAccessor().RevokeToken(token)
}

func UserpassLogin(username, password string) (*AccessToken, error) {
	return NewAuthorizationAccessor().Login(username, password)
}
