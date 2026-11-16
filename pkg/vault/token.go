package vault

import (
	"time"

	"github.com/hashicorp/vault/api"
)

// AccessToken =========================================================================================================

// AccessToken is a Vault token usable to read exactly one holder's claims.
type AccessToken struct {
	Token     string
	ExpiresAt time.Time
}

func NewAccessToken(token string) *AccessToken {
	return &AccessToken{
		Token:     token,
		ExpiresAt: time.Now().Add(5 * time.Minute),
	}
}

func NewAccessTokenFromAuth(auth *api.SecretAuth) *AccessToken {
	return &AccessToken{
		Token:     auth.ClientToken,
		ExpiresAt: time.Now().Add(time.Duration(auth.LeaseDuration) * time.Second),
	}
}
