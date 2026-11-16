package oid4vci

import (
	"fmt"

	"github.com/go-jose/go-jose/v4"
	"github.com/tdiesler/nessus-oid4vc-go/pkg/vault"
)

// TransitSigner ============================================================================================================

// TransitSigner is a jose.OpaqueSigner backed by Vault's transit secrets
// engine: id_token signing operations never touch a private key locally,
// matching this project's architecture decision that the issuer service
// never holds a private key — Vault always signs.
type TransitSigner struct {
	accessor *vault.TransitAccessor
	keyName  string
	public   *jose.JSONWebKey
}

// NewTransitSigner constructs a TransitSigner for keyName, fetching its
// current public key from Vault so JWKS lookups need no further round trip.
func NewTransitSigner(keyName string) (*TransitSigner, error) {
	accessor := vault.NewTransitAccessor()
	pub, err := accessor.PublicKey(keyName)
	if err != nil {
		return nil, fmt.Errorf("transit signer %q: %w", keyName, err)
	}

	return &TransitSigner{
		accessor: accessor,
		keyName:  keyName,
		public: &jose.JSONWebKey{
			Key:       pub,
			KeyID:     keyName,
			Algorithm: string(jose.ES256),
			Use:       "sig",
		},
	}, nil
}

// Algs returns the signature algorithms this signer supports — a
// jose.OpaqueSigner method.
func (s *TransitSigner) Algs() []jose.SignatureAlgorithm {
	return []jose.SignatureAlgorithm{jose.ES256}
}

// JWKS returns the public half of this signer's key as a JSON Web Key Set,
// suitable for serving at a /jwks.json-style endpoint.
func (s *TransitSigner) JWKS() *jose.JSONWebKeySet {
	return &jose.JSONWebKeySet{Keys: []jose.JSONWebKey{*s.public}}
}

// Public returns the signer's current public key — a jose.OpaqueSigner
// method.
func (s *TransitSigner) Public() *jose.JSONWebKey {
	return s.public
}

// SignPayload signs payload — the JWS signing input, not a raw claims body —
// with Vault transit's current key for keyName. A jose.OpaqueSigner method.
func (s *TransitSigner) SignPayload(payload []byte, alg jose.SignatureAlgorithm) ([]byte, error) {
	if alg != jose.ES256 {
		return nil, fmt.Errorf("transit signer %q: unsupported algorithm %s", s.keyName, alg)
	}
	return s.accessor.Sign(s.keyName, payload)
}
