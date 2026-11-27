// Package jwtvc builds jwt_vc_json credentials (OID4VCI's JWT-encoded,
// non-JSON-LD W3C Verifiable Credential format), per VC Data Model 1.1's
// JWT encoding (§6.3.1): a signed JWT carrying a "vc" claim, with the VC's
// issuer/issuanceDate/credentialSubject.id properties represented only via
// the standard iss/nbf/sub claims rather than duplicated inside "vc", per
// that section's own encoding guidance. Signing goes through a
// jose.SigningKey, so a jose.OpaqueSigner such as oid4vci.TransitSigner
// plugs in without this package ever touching a private key.
package jwtvc

import (
	"fmt"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

// vcContext is this package's sole "@context" entry, per VC Data Model
// 1.1's required base context.
const vcContext = "https://www.w3.org/2018/credentials/v1"

// Builder ====================================================================================================================

// Builder assembles one jwt_vc_json credential.
type Builder struct {
	vct       string
	signer    jose.Signer
	issuer    string
	subject   string
	holderKey *jose.JSONWebKey
	claims    map[string]any
}

// NewBuilder constructs a Builder for a credential of type vct, signed with
// signingKey — typically a Vault Transit-backed jose.OpaqueSigner in
// production, a raw private key in tests.
func NewBuilder(vct string, signingKey jose.SigningKey) (*Builder, error) {
	if vct == "" {
		return nil, fmt.Errorf("jwtvc: vct is required")
	}

	signer, err := jose.NewSigner(signingKey, (&jose.SignerOptions{}).WithType("JWT"))
	if err != nil {
		return nil, fmt.Errorf("jwtvc: build signer: %w", err)
	}

	return &Builder{
		vct:    vct,
		signer: signer,
		claims: map[string]any{},
	}, nil
}

// WithClaim adds a claim to the credential's credentialSubject.
func (b *Builder) WithClaim(name string, value any) *Builder {
	b.claims[name] = value
	return b
}

// WithHolderBinding binds the credential to holderKey's public half via a
// "cnf" claim, so a verifier can require proof of possession from the
// presenting holder.
func (b *Builder) WithHolderBinding(holderKey jose.JSONWebKey) *Builder {
	public := holderKey.Public()
	b.holderKey = &public
	return b
}

// WithIssuer sets the credential's issuer ("iss" claim, mapping to the VC's
// own "issuer" property).
func (b *Builder) WithIssuer(issuer string) *Builder {
	b.issuer = issuer
	return b
}

// WithSubject sets the credential's subject ("sub" claim, mapping to the
// VC's own "credentialSubject.id" property).
func (b *Builder) WithSubject(subject string) *Builder {
	b.subject = subject
	return b
}

// Build signs b's claims and returns the compact JWS serialization.
func (b *Builder) Build() (string, error) {
	claims := credentialClaims{
		Claims: jwt.Claims{
			Issuer:    b.issuer,
			Subject:   b.subject,
			NotBefore: jwt.NewNumericDate(time.Now()),
		},
		Vc: verifiableCredential{
			Context:           []string{vcContext},
			Type:              []string{"VerifiableCredential", b.vct},
			CredentialSubject: b.claims,
		},
	}
	if b.holderKey != nil {
		claims.Cnf = &confirmation{Jwk: b.holderKey}
	}

	signedJwt, err := jwt.Signed(b.signer).Claims(claims).Serialize()
	if err != nil {
		return "", fmt.Errorf("jwtvc: sign: %w", err)
	}
	return signedJwt, nil
}

// Private ---------------------------------------------------------------------------------------------------------------

// confirmation is a "cnf" claim's value: the holder key a credential is
// bound to.
type confirmation struct {
	Jwk *jose.JSONWebKey `json:"jwk"`
}

// verifiableCredential is a "vc" claim's value: the VC's properties not
// already carried by a registered JWT claim (see credentialClaims) —
// issuer, issuanceDate, and credentialSubject.id are deliberately omitted
// here, mapped instead to "iss", "nbf", and "sub" respectively.
type verifiableCredential struct {
	Context           []string       `json:"@context"`
	Type              []string       `json:"type"`
	CredentialSubject map[string]any `json:"credentialSubject"`
}

// credentialClaims is a jwt_vc_json credential's full signed claims set:
// VC Data Model 1.1's registered-claim mapping (iss/sub/nbf, via
// jwt.Claims), OID4VCI's holder-key binding ("cnf"), and the "vc" claim
// itself.
type credentialClaims struct {
	jwt.Claims
	Cnf *confirmation        `json:"cnf,omitempty"`
	Vc  verifiableCredential `json:"vc"`
}
