package oauth

import (
	"net/http"

	"github.com/tdiesler/nessus-oid4vc-go/pkg/utils"
)

// UserInfoAccessor ====================================================================================================

// UserInfoAccessor accesses an authorization server's UserInfo endpoint
// (OIDC Core 1.0 §5.3): an OAuth 2.0 protected resource that returns claims
// about the authenticated end-user, given a valid access token.
type UserInfoAccessor struct {
	httpClient *http.Client
}

// NewUserInfoAccessor constructs a UserInfoAccessor.
func NewUserInfoAccessor() (*UserInfoAccessor, error) {
	return &UserInfoAccessor{httpClient: http.DefaultClient}, nil
}

// Fetch retrieves claims about the end-user accessToken was issued for, from
// userinfoEndpoint, authenticating with accessToken as a Bearer token.
func (a *UserInfoAccessor) Fetch(userinfoEndpoint, accessToken string) (map[string]any, error) {
	req := utils.NewHttpGetRequest(userinfoEndpoint)
	req.WithBearerAuth(accessToken)
	return req.Fetch[map[string]any](a.httpClient)
}
