package utils

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

// AbstractHttpRequest =================================================================================================

// abstractHttpRequest is the state shared by every outbound HTTP request in this
// package: where to send it, and (optionally) an Authorization header.
// Meant to be embedded by a concrete request type (HttpGetRequest,
// HttpPostRequest, ...) that adds its own verb-specific behavior.
type abstractHttpRequest struct {
	Endpoint      string
	Authorization string
}

// WithBasicAuth sets the Authorization header to HTTP Basic auth with
// username/password.
func (r *abstractHttpRequest) WithBasicAuth(username, password string) {
	auth := username + ":" + password
	r.Authorization = "Basic " + base64.StdEncoding.EncodeToString([]byte(auth))
}

// WithBearerAuth sets the Authorization header to a Bearer token.
func (r *abstractHttpRequest) WithBearerAuth(token string) {
	r.Authorization = "Bearer " + token
}

// HttpGetRequest ======================================================================================================

// HttpGetRequest is a GET: an endpoint to fetch. Meant to be embedded by a
// concrete request type that owns its own specific parameters, turns them
// into URL query values via WithParam, and calls Fetch.
type HttpGetRequest struct {
	abstractHttpRequest
	Params url.Values
}

func NewHttpGetRequest(endpoint string) *HttpGetRequest {
	return &HttpGetRequest{Endpoint: endpoint, Params: url.Values{}}
}

// WithParam adds a query parameter, returning r for chaining.
func (r *HttpGetRequest) WithParam(key, value string) *HttpGetRequest {
	r.Params.Add(key, value)
	return r
}

// Fetch executes a GET of r.Endpoint with r.Params appended as a query
// string (merged with any query string r.Endpoint already has),
// authenticating with HTTP Basic auth when r.Authorization is non-empty,
// and JSON-decodes a 2xx response as T.
func (r *HttpGetRequest) Fetch[T any](httpClient *http.Client) (T, error) {
	var result T

	u, err := url.Parse(r.Endpoint)
	if err != nil {
		return result, fmt.Errorf("parse endpoint %q: %w", r.Endpoint, err)
	}
	if len(r.Params) > 0 {
		q := u.Query()
		for key, values := range r.Params {
			for _, value := range values {
				q.Add(key, value)
			}
		}
		u.RawQuery = q.Encode()
	}

	req, err := http.NewRequest(http.MethodGet, u.String(), nil)
	if err != nil {
		return result, err
	}
	if r.Authorization != "" {
		req.Header.Set("Authorization", r.Authorization)
	}

	resp, err := httpClient.Do(req)
	if err != nil {
		return result, err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return result, fmt.Errorf("GET %s: %s: %s", u.String(), resp.Status, body)
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return result, fmt.Errorf("GET %s: decode response: %w", u.String(), err)
	}
	return result, nil
}

// HttpPostRequest =====================================================================================================

// HttpPostRequest is a form-encoded POST: an endpoint to post it to. Meant
// to be embedded by a concrete request type that owns its own specific
// parameters, turns them into form values, and calls post.
type HttpPostRequest struct {
	abstractHttpRequest
}

// Post executes a form-encoded POST of form to r.Endpoint, authenticating
// with HTTP Basic auth when username is non-empty, and JSON-decodes a 2xx
// response as T.
func (r *HttpPostRequest) Post[T any](httpClient *http.Client, form url.Values) (T, error) {
	var result T

	req, err := http.NewRequest(http.MethodPost, r.Endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return result, err
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if r.Authorization != "" {
		req.Header.Set("Authorization", r.Authorization)
	}

	resp, err := httpClient.Do(req)
	if err != nil {
		return result, err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return result, fmt.Errorf("POST %s: %s: %s", r.Endpoint, resp.Status, body)
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return result, err
	}

	return result, nil
}
