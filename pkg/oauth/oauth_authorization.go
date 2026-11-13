package oauth

import (
	"fmt"
	"net/url"

	"github.com/tdiesler/nessus-oid4vc-go/pkg/config"
	"github.com/tdiesler/nessus-oid4vc-go/pkg/oid4vci"
)

// OAuthAuthorizationRequest ===========================================================================================

// OAuthAuthorizationRequest is a general OAuth 2.0 Authorization Request: a GET
// against an authorization server's authorization endpoint. The shape is
// shared across grant types (Authorization Code, RFC 6749 §4.1.1; Implicit,
// §4.2.1; ...) — they differ only in response_type.
type OAuthAuthorizationRequest struct {
	Endpoint string

	// ClientId is REQUIRED.
	ClientId string
	// ResponseType is REQUIRED; "code" for the Authorization Code grant.
	ResponseType string

	// RedirectUri is OPTIONAL.
	RedirectUri string
	// Scope is OPTIONAL.
	Scope string
}

// NewOAuthAuthorizationRequest constructs an OAuthAuthorizationRequest. endpoint and
// clientId are required, as is response_type — defaulted here to "code"
// (the Authorization Code grant) as a convenience; override it via
// WithResponseType for other grants. redirectUri and scope are optional,
// left to the With* methods.
func NewOAuthAuthorizationRequest(endpoint, clientId string) *OAuthAuthorizationRequest {
	return &OAuthAuthorizationRequest{
		Endpoint:     endpoint,
		ClientId:     clientId,
		ResponseType: "code",
	}
}

func (req *OAuthAuthorizationRequest) WithRedirectUri(redirectUri string) *OAuthAuthorizationRequest {
	req.RedirectUri = redirectUri
	return req
}

func (req *OAuthAuthorizationRequest) WithResponseType(responseType string) *OAuthAuthorizationRequest {
	req.ResponseType = responseType
	return req
}

func (req *OAuthAuthorizationRequest) WithScope(scope string) *OAuthAuthorizationRequest {
	req.Scope = scope
	return req
}

// ToRequestUrl renders the request as the URL a user-agent is sent to.
// RedirectUri and Scope are omitted entirely when unset, since they're
// optional — unlike an empty client_id or response_type, an empty
// redirect_uri/scope parameter is not the same thing as omitting it.
func (req *OAuthAuthorizationRequest) ToRequestUrl() string {
	q := url.Values{}
	q.Set("client_id", req.ClientId)
	q.Set("response_type", req.ResponseType)
	if req.RedirectUri != "" {
		q.Set("redirect_uri", req.RedirectUri)
	}
	if req.Scope != "" {
		q.Set("scope", req.Scope)
	}
	return req.Endpoint + "?" + q.Encode()
}

// OAuthAuthorizationAccessor ==========================================================================================

// OAuthAuthorizationAccessor accesses Vault's OAuth endpoint.
type OAuthAuthorizationAccessor struct {
}

// NewOAuthAuthorizationAccessor constructs an OAuthAuthorizationAccessor
func NewOAuthAuthorizationAccessor() (*OAuthAuthorizationAccessor, error) {
	return &OAuthAuthorizationAccessor{}, nil
}

// CodeFlowAuthorization drives an OAuth 2.0 Authorization Code flow against
// Vault's own OIDC provider, the way a wallet would, and returns the
// resulting authorization code. The interactive login itself is delegated
// to a BrowserAuthorizer.
func (s *OAuthAuthorizationAccessor) CodeFlowAuthorization(client, scope, username, password string) (string, error) {
	cfg, err := config.GetAppConfig()
	if err != nil {
		return "", err
	}

	// Discover the authorization endpoint.
	discovery, err := NewWellKnownAccessor()
	if err != nil {
		return "", err
	}
	metadata, err := discovery.AuthorizationServerMetadata()
	if err != nil {
		return "", fmt.Errorf("discover authorization server metadata: %w", err)
	}

	// Resolve the client's id.
	clientId, err := oid4vci.DiscoverClientId(client)
	if err != nil {
		return "", err
	}

	// Build the Authorization Request.
	authReq := NewOAuthAuthorizationRequest(metadata.AuthorizationEndpoint, clientId).
		WithRedirectUri(cfg.RedirectURI).
		WithScope(scope)

	// Complete it interactively, as a wallet's user-agent would.
	authorizer, err := NewChromeAuthorizer()
	if err != nil {
		return "", err
	}
	return authorizer.Authorize(authReq, username, password)
}
