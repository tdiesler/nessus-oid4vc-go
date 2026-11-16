package oauth

import (
	"fmt"
	"net/http"
	"net/url"

	co "github.com/tdiesler/nessus-oid4vc-go/pkg/common"
	"github.com/tdiesler/nessus-oid4vc-go/pkg/vault"
)

// OAuth TokenRequest ==================================================================================================

// TokenRequest is an OAuth 2.0 Access Token Request for the Authorization
// Code grant (RFC 6749 §4.1.3), authenticated with the client's credentials
// (RFC 6749 §2.3.1's "client_secret_basic" method).
type TokenRequest struct {
	co.HttpPostRequest
	Code         string
	ClientId     string
	ClientSecret string
	GrantType    string
	RedirectUri  string
}

// NewTokenRequest constructs an TokenRequest for the Authorization Code
// grant against endpoint, authenticating as clientId/clientSecret.
func NewTokenRequest(endpoint, code, redirectUri, clientId, clientSecret string) *TokenRequest {
	return &TokenRequest{
		Endpoint:     endpoint,
		GrantType:    "authorization_code",
		Code:         code,
		RedirectUri:  redirectUri,
		ClientId:     clientId,
		ClientSecret: clientSecret,
	}
}

// Send performs the Access Token Request and returns the resulting tokens.
func (r *TokenRequest) Send(httpClient *http.Client) (*TokenResponse, error) {

	// Build the Access Token Request's form body.
	form := url.Values{}
	form.Set("grant_type", r.GrantType)
	form.Set("code", r.Code)
	form.Set("redirect_uri", r.RedirectUri)

	// Authenticate as the client, when credentials are available.
	if r.ClientId != "" && r.ClientSecret != "" {
		r.WithBasicAuth(r.ClientId, r.ClientSecret)
	}

	// Redeem the code.
	token, err := r.Post[TokenResponse](httpClient, form)
	if err != nil {
		return nil, err
	}

	return &token, nil
}

// OAuth TokenResponse =================================================================================================

// TokenResponse is an OAuth 2.0 Access Token Response (RFC 6749 §4.1.4 /
// §5.1), returned by the authorization server's token endpoint.
type TokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	IdToken     string `json:"id_token"`
	ExpiresIn   int    `json:"expires_in"`
}

// OAuth TokenAccessor =================================================================================================

// TokenAccessor accesses an authorization server's token endpoint,
// e.g. to redeem an authorization code for tokens.
type TokenAccessor struct {
	httpClient *http.Client
}

// NewTokenAccessor constructs an TokenAccessor, reusing
// Vault's own configured (TLS-aware) HTTP client rather than http.DefaultClient
// — the token endpoint lives on the same server, it just doesn't speak
// Vault's request/response envelope (no X-Vault-Token, no JSON body), so we
// still build the request by hand instead of going through Logical().
func NewTokenAccessor() (*TokenAccessor, error) {
	client, err := vault.NewClient()
	if err != nil {
		return nil, err
	}
	return &TokenAccessor{httpClient: client.CloneConfig().HttpClient}, nil
}

// ExchangeAuthorizationCode redeems code for tokens at the named OIDC
// client's discovered authorization server token endpoint.
func (a *TokenAccessor) ExchangeAuthorizationCode(clientName, code, redirectUri string) (*TokenResponse, error) {

	// Discover the token endpoint.
	discovery, err := NewWellKnownAccessor()
	if err != nil {
		return nil, err
	}
	metadata, err := discovery.AuthorizationServerMetadata()
	if err != nil {
		return nil, fmt.Errorf("discover authorization server metadata: %w", err)
	}

	// Resolve the client's credentials.
	clientId, err := vault.DiscoverClientId(clientName)
	if err != nil {
		return nil, err
	}
	clientSecret, err := vault.DiscoverClientSecret(clientName)
	if err != nil {
		return nil, err
	}

	// Redeem the code.
	req := NewTokenRequest(metadata.TokenEndpoint, code, redirectUri, clientId, clientSecret)
	return req.Send(a.httpClient)
}
