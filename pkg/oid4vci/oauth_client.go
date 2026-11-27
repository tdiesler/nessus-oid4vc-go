package oid4vci

import (
	"bytes"
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

// OAuthClient drives an OAuth 2.0 Authorization Code flow against a
// CredentialIssuer from the client's side — the role a holder plays
// against this service, as a public client (RFC 6749 §2.1), with no
// secret. Unlike Client (this server's registration record for a caller),
// OAuthClient is the caller itself; it has no dependency on testing and is
// just as usable from a real holder simulator or CLI as from a test.
type OAuthClient struct {
	baseUrl     string
	clientId    string
	redirectUri string
	scope       string
	httpClient  *http.Client
}

// NewOAuthClient constructs an OAuthClient for the authorization server at
// baseURL, identifying itself as clientId.
func NewOAuthClient() (*OAuthClient, error) {

	cfg, err := co.GetAppConfig()
	if err != nil {
		return nil, err
	}

	baseUrl := cfg.Oid4vciAddr
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

// WithScope sets the scope c.Authorize requests.
func (c *OAuthClient) WithScope(scope string) *OAuthClient {
	c.scope = scope
	return c
}

// Authorize submits username/password to /authorize, the way a holder's
// user-agent submitting a rendered login form would, and returns the
// resulting authorization code from the redirect callback.
func (c *OAuthClient) Authorize(username, password string) (string, error) {
	form := url.Values{
		"client_id":    {c.clientId},
		"redirect_uri": {c.redirectUri},
		"scope":        {c.scope},
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

// FetchCredential requests a credential from /credential, naming it by
// credentialIdentifier (from authorization_details), proving possession of
// a holder key via proofJwt, and authenticating with accessToken. Returns
// the issued credential string.
func (c *OAuthClient) FetchCredential(accessToken, credentialIdentifier, proofJwt string) (string, error) {
	reqBody := credentialRequest{CredentialIdentifier: credentialIdentifier}
	reqBody.Proofs.Jwt = []string{proofJwt}
	data, err := json.Marshal(reqBody)
	if err != nil {
		return "", fmt.Errorf("fetch credential: %w", err)
	}

	req, err := http.NewRequest(http.MethodPost, c.baseUrl+"/credential", bytes.NewReader(data))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+accessToken)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("fetch credential: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("fetch credential: read response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("fetch credential: %s: %s", resp.Status, body)
	}

	var cred credentialResponse
	if err := json.Unmarshal(body, &cred); err != nil {
		return "", fmt.Errorf("fetch credential: decode response: %w", err)
	}
	if len(cred.Credentials) == 0 {
		return "", fmt.Errorf("fetch credential: no credentials in response")
	}
	return cred.Credentials[0].Credential, nil
}

// FetchCredentialIssuerMetadata fetches the authorization server's OID4VCI
// credential issuer metadata document.
func (c *OAuthClient) FetchCredentialIssuerMetadata() (*co.CredentialIssuerMetadata, error) {
	req := co.NewHttpGetRequest(c.baseUrl + "/.well-known/openid-credential-issuer")
	metadata, err := req.Fetch[co.CredentialIssuerMetadata](c.httpClient)
	if err != nil {
		return nil, fmt.Errorf("fetch credential issuer metadata: %w", err)
	}
	return &metadata, nil
}

// FetchJWKS fetches the authorization server's JWKS document.
func (c *OAuthClient) FetchJWKS() (*jose.JSONWebKeySet, error) {
	return co.FetchJWKS(c.httpClient, c.baseUrl+"/jwks.json")
}

// FetchNonce fetches a fresh c_nonce from /nonce, required to bind the next
// key-proof JWT to the credential request it accompanies.
func (c *OAuthClient) FetchNonce() (string, error) {
	resp, err := c.httpClient.Post(c.baseUrl+"/nonce", "application/json", nil)
	if err != nil {
		return "", fmt.Errorf("fetch nonce: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("fetch nonce: %s: %s", resp.Status, body)
	}

	var nonce nonceResponse
	if err := json.NewDecoder(resp.Body).Decode(&nonce); err != nil {
		return "", fmt.Errorf("fetch nonce: decode response: %w", err)
	}
	return nonce.CNonce, nil
}

// RefreshToken redeems refreshToken at /token for a new TokenResponse,
// identifying itself as c.clientId.
func (c *OAuthClient) RefreshToken(refreshToken string) (*TokenResponse, error) {
	form := url.Values{
		"grant_type":    {"refresh_token"},
		"client_id":     {c.clientId},
		"refresh_token": {refreshToken},
	}
	req, err := http.NewRequest(http.MethodPost, c.baseUrl+"/token", strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("refresh token: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("refresh token: read response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("refresh token: %s: %s", resp.Status, body)
	}

	var token TokenResponse
	if err := json.Unmarshal(body, &token); err != nil {
		return nil, fmt.Errorf("refresh token: decode response: %w", err)
	}
	return &token, nil
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
