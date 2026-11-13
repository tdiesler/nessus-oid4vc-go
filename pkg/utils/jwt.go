package utils

import (
	"encoding/json"
	"fmt"
	"net/http"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

// signatureAlgorithms lists the "alg" values accepted when verifying a
// JWT's signature.
var signatureAlgorithms = []jose.SignatureAlgorithm{
	jose.RS256, jose.RS384, jose.RS512,
	jose.ES256, jose.ES384, jose.ES512,
	jose.EdDSA,
}

// FetchJWKS fetches and decodes a JSON Web Key Set from jwksUri.
func FetchJWKS(httpClient *http.Client, jwksUri string) (*jose.JSONWebKeySet, error) {
	resp, err := httpClient.Get(jwksUri)
	if err != nil {
		return nil, fmt.Errorf("fetch JWKS: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("fetch JWKS: GET %s: %s", jwksUri, resp.Status)
	}

	var jwks jose.JSONWebKeySet
	if err = json.NewDecoder(resp.Body).Decode(&jwks); err != nil {
		return nil, fmt.Errorf("fetch JWKS: decode response: %w", err)
	}
	return &jwks, nil
}

// VerifyJWT verifies token's signature against jwks and returns its claims.
func VerifyJWT(token string, jwks *jose.JSONWebKeySet) (map[string]any, error) {
	parsed, err := jwt.ParseSigned(token, signatureAlgorithms)
	if err != nil {
		return nil, fmt.Errorf("parse JWT: %w", err)
	}

	var claims map[string]any
	if err := parsed.Claims(jwks, &claims); err != nil {
		return nil, fmt.Errorf("verify JWT: %w", err)
	}
	return claims, nil
}
