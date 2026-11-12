package oid4vci

import (
	"fmt"
)

// AuthorizationAccessor accesses Vault's OAuth endpoint.
type AuthorizationAccessor struct {
}

// NewAuthorizationAccessor constructs an AuthorizationAccessor
func NewAuthorizationAccessor() (*AuthorizationAccessor, error) {
	return &AuthorizationAccessor{}, nil
}

// DirectAuthorization login via Vault's userpass auth method,
// equivalent to `vault login -method=userpass`.
func (s *AuthorizationAccessor) DirectAuthorization(username, password string) (*AccessToken, error) {
	//client, err := NewClient()
	//if err != nil {
	//	return nil, err
	//}

	return nil, fmt.Errorf("direct authorization - not implemented")
}
