package oid4vci

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/go-jose/go-jose/v4"
	co "github.com/tdiesler/nessus-oid4vc-go/pkg/common"
)

// OAuthClient ===============================================================================================================

// OAuthClient drives an OAuth 2.0 Authorization Code flow against an
// AuthorizationServer from the client's side — the role a wallet plays
// against this service, as a public client (RFC 6749 §2.1), with no
// secret. Unlike Client (this server's registration record for a caller),
// OAuthClient is the caller itself; it has no dependency on testing and is
// just as usable from a real wallet simulator or CLI as from a test.
type OAuthClient struct {
	baseUrl     string
	clientId    string
	redirectUri string
	httpClient  *http.Client
}

// NewOAuthClient constructs an OAuthClient for the authorization server at
// baseURL, identifying itself as clientId.
func NewOAuthClient() (*OAuthClient, error) {

	cfg, err := co.GetAppConfig()
	if err != nil {
		return nil, err
	}

	baseUrl := "http://" + cfg.Oid4vciAddr
	redirectUri := cfg.RedirectUri

	client := OAuthClient{
		baseUrl:     baseUrl,
		clientId:    cfg.OidcClient,
		redirectUri: redirectUri,
		httpClient: &http.Client{
			// /authorize responds with a redirect carrying the authorization
			// code in its query string — the thing Authorize needs to read,
			// not follow.
			CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse },
		},
	}
	return &client, nil
}

// Authorize submits username/password to /authorize, the way a wallet's
// user-agent submitting a rendered login form would, and returns the
// resulting authorization code from the redirect callback.
func (c *OAuthClient) Authorize(username, password string) (string, error) {
	form := url.Values{
		"client_id":    {c.clientId},
		"redirect_uri": {c.redirectUri},
		"username":     {username},
		"password":     {password},
	}
	resp, err := c.httpClient.PostForm(c.baseUrl+"/authorize", form)
	if err != nil {
		return "", fmt.Errorf("authorize: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusFound {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("authorize: %s: %s", resp.Status, body)
	}

	callback, err := url.Parse(resp.Header.Get("Location"))
	if err != nil {
		return "", fmt.Errorf("authorize: parse callback redirect: %w", err)
	}
	code := callback.Query().Get("code")
	if code == "" {
		return "", fmt.Errorf("authorize: no code in callback redirect")
	}
	return code, nil
}

// ExchangeCode redeems code at /token, identifying itself as c.clientId.
func (c *OAuthClient) ExchangeCode(code string) (*TokenResponse, error) {
	form := url.Values{
		"grant_type":   {"authorization_code"},
		"client_id":    {c.clientId},
		"code":         {code},
		"redirect_uri": {c.redirectUri},
	}
	req, err := http.NewRequest(http.MethodPost, c.baseUrl+"/token", strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("exchange code: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("exchange code: read response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("exchange code: %s: %s", resp.Status, body)
	}

	var token TokenResponse
	if err := json.Unmarshal(body, &token); err != nil {
		return nil, fmt.Errorf("exchange code: decode response: %w", err)
	}
	return &token, nil
}

// FetchJWKS fetches the authorization server's JWKS document.
func (c *OAuthClient) FetchJWKS() (*jose.JSONWebKeySet, error) {
	return co.FetchJWKS(c.httpClient, c.baseUrl+"/jwks.json")
}

// UserInfo fetches claims for accessToken from /userinfo.
func (c *OAuthClient) UserInfo(accessToken string) (map[string]any, error) {
	req, err := http.NewRequest(http.MethodGet, c.baseUrl+"/userinfo", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("userinfo: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("userinfo: %s: %s", resp.Status, body)
	}

	var claims map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&claims); err != nil {
		return nil, fmt.Errorf("userinfo: decode response: %w", err)
	}
	return claims, nil
}
