package oid4vci

import (
	"fmt"
	"time"
)

// AccessToken ---------------------------------------------------------------------------------------------------------

// AccessToken is a Vault token usable to read exactly one holder's claims.
type AccessToken struct {
	Token     string
	ExpiresAt time.Time
}

func NewAccessToken(token string) (*AccessToken, error) {
	return &AccessToken{
		Token:     token,
		ExpiresAt: time.Now().Add(5 * time.Minute),
	}, nil
}

func (t *AccessToken) WithExpiresAt(expiresAt time.Time) *AccessToken {
	t.ExpiresAt = expiresAt
	return t
}

// TokenAccessor -------------------------------------------------------------------------------------------------------

// TokenAccessor accesses Vault's token endpoint.
type TokenAccessor struct {
}

// AccessToken exchanges an authorization code for an access token.
func (s *TokenAccessor) AccessToken(code string) (*AccessToken, error) {
	client, err := NewClient()
	if err != nil {
		return nil, err
	}

	secret, err := client.Logical().Unwrap(code)
	if err != nil {
		return nil, fmt.Errorf("oid4vci: redeem pre-authorized code: %w", err)
	}
	if secret == nil || secret.Auth == nil {
		return nil, fmt.Errorf("oid4vci: redeem pre-authorized code: no auth in response")
	}

	token, err := NewAccessToken(secret.Auth.ClientToken)
	if err != nil {
		return nil, err
	}
	token.WithExpiresAt(time.Now().Add(time.Duration(secret.LeaseDuration) * time.Second))
	return token, err
}
