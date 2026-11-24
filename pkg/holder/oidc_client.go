package holder

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	co "github.com/tdiesler/nessus-oid4vc-go/pkg/common"
)

// Functions ---------------------------------------------------------------------------------------------------------

// discoverMetadata fetches issuerURL's OpenID Connect discovery document.
func discoverMetadata(issuerURL string) (*co.AuthorizationServerMetadata, error) {
	req := co.NewHttpGetRequest(issuerURL + "/.well-known/openid-configuration")
	metadata, err := req.Fetch[co.AuthorizationServerMetadata](http.DefaultClient)
	if err != nil {
		return nil, fmt.Errorf("discover %s: %w", issuerURL, err)
	}
	return &metadata, nil
}

// EndSession revokes token's session at endSessionEndpoint (Keycloak's
// logout endpoint), authenticating as clientId. Keycloak answers with 204
// No Content, so this doesn't go through co.HttpPostRequest.Post, which
// always expects a JSON body.
func endSession(endSessionEndpoint, clientId string, token *Token) error {
	form := url.Values{}
	form.Set("client_id", clientId)
	form.Set("refresh_token", token.RefreshToken)

	resp, err := http.PostForm(endSessionEndpoint, form)
	if err != nil {
		return fmt.Errorf("end session: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("end session: %s: %s", resp.Status, body)
	}
	return nil
}

// exchangeAuthorizationCode redeems code for tokens at tokenEndpoint,
// authenticating as clientId — a public client, so no client secret. It
// also returns any authorization_details the token response carries
// (RFC 9396), naming the credential(s) this session is now entitled to.
func exchangeAuthorizationCode(tokenEndpoint, clientId, code, redirectUri string) (*Token, []AuthorizationDetail, error) {
	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("client_id", clientId)
	form.Set("code", code)
	form.Set("redirect_uri", redirectUri)

	req := co.HttpPostRequest{Endpoint: tokenEndpoint}
	body, err := req.Post[tokenResponse](http.DefaultClient, form)
	if err != nil {
		return nil, nil, fmt.Errorf("exchange authorization code: %w", err)
	}
	token := NewToken(body.AccessToken, body.RefreshToken, time.Now().Add(time.Duration(body.ExpiresIn)*time.Second))
	return token, body.AuthorizationDetails, nil
}

// refreshToken redeems token's refresh token for a new Token at
// tokenEndpoint, authenticating as clientId — a public client, so no
// client secret. Keycloak issues a new refresh token alongside the new
// access token (RFC 6749 §6), so callers must replace their stored Token
// with the one returned here, not just its access token.
func refreshToken(tokenEndpoint, clientId string, token *Token) (*Token, []AuthorizationDetail, error) {
	form := url.Values{}
	form.Set("grant_type", "refresh_token")
	form.Set("client_id", clientId)
	form.Set("refresh_token", token.RefreshToken)

	req := co.HttpPostRequest{Endpoint: tokenEndpoint}
	body, err := req.Post[tokenResponse](http.DefaultClient, form)
	if err != nil {
		return nil, nil, fmt.Errorf("refresh token: %w", err)
	}
	refreshed := NewToken(body.AccessToken, body.RefreshToken, time.Now().Add(time.Duration(body.ExpiresIn)*time.Second))
	return refreshed, body.AuthorizationDetails, nil
}

// revokeToken revokes token at revocationEndpoint (RFC 7009), identifying
// itself as clientId — a public client, so no client secret.
func revokeToken(revocationEndpoint, clientId, token string) error {
	form := url.Values{}
	form.Set("token", token)
	form.Set("client_id", clientId)

	resp, err := http.PostForm(revocationEndpoint, form)
	if err != nil {
		return fmt.Errorf("revoke token: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("revoke token: %s: %s", resp.Status, body)
	}
	return nil
}

// tokenResponse is the OAuth 2.0 Access Token Response (RFC 6749 §4.1.4)
// shape returned by an authorization server's token endpoint.
type tokenResponse struct {
	AccessToken          string                `json:"access_token"`
	RefreshToken         string                `json:"refresh_token"`
	ExpiresIn            int64                 `json:"expires_in"`
	AuthorizationDetails []AuthorizationDetail `json:"authorization_details,omitempty"`
}
