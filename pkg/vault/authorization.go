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

// Functions -----------------------------------------------------------------------------------------------------------

func UserpassLogin(username, password string) (*AccessToken, error) {
	return NewAuthorizationAccessor().Login(username, password)
}
