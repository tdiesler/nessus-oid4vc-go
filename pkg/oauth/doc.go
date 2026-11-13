// Package oauth drives the client side of an OAuth 2.0 / OpenID Connect
// Authorization Code flow against Vault's own OIDC provider: discovering
// its endpoints via the well-known metadata document, completing the
// browser-driven login at the authorization endpoint, exchanging the
// resulting code at the token endpoint, and fetching claims from the
// UserInfo endpoint.
package oauth
