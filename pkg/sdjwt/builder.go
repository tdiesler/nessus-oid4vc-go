// Package sdjwt builds SD-JWT VCs (draft-ietf-oauth-sd-jwt-vc, "dc+sd-jwt"):
// an issuer-signed JWT naming selectively-disclosable claims only by their
// digest, each paired with a disclosure the holder chooses whether to
// reveal to a verifier. Signing goes through a jose.SigningKey, so a
// jose.OpaqueSigner such as oid4vci.TransitSigner plugs in without this
// package ever touching a private key.
package sdjwt

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

// sdJwtVcType is the typ header identifying an SD-JWT VC, per
// draft-ietf-oauth-sd-jwt-vc.
const sdJwtVcType = "dc+sd-jwt"

// sdAlgSha256 is the only digest algorithm this package produces, named by
// the signed JWT's "_sd_alg" claim.
const sdAlgSha256 = "sha-256"

// Builder ====================================================================================================================

// Builder assembles one SD-JWT VC. Claims added via WithClaim stay in the
// signed JWT body; claims added via WithDisclosableClaim are replaced
// there by a digest, recoverable only via the matching disclosure Build
// appends to the compact serialization.
type Builder struct {
	vct               string
	signer            jose.Signer
	issuer            string
	subject           string
	expiry            time.Time
	holderKey         *jose.JSONWebKey
	claims            map[string]any
	disclosableClaims map[string]any
}

// NewBuilder constructs a Builder for a credential of type vct, signed with
// signingKey — typically a Vault Transit-backed jose.OpaqueSigner in
// production, a raw private key in tests.
func NewBuilder(vct string, signingKey jose.SigningKey) (*Builder, error) {
	if vct == "" {
		return nil, fmt.Errorf("sdjwt: vct is required")
	}

	signer, err := jose.NewSigner(signingKey, (&jose.SignerOptions{}).WithType(sdJwtVcType))
	if err != nil {
		return nil, fmt.Errorf("sdjwt: build signer: %w", err)
	}

	return &Builder{
		vct:               vct,
		signer:            signer,
		claims:            map[string]any{},
		disclosableClaims: map[string]any{},
	}, nil
}

// WithClaim adds an always-visible claim to the signed JWT body.
func (b *Builder) WithClaim(name string, value any) *Builder {
	b.claims[name] = value
	return b
}

// WithDisclosableClaim adds a selectively-disclosable claim: Build replaces
// it in the signed JWT body with a digest and appends the disclosure that
// recovers name and value.
func (b *Builder) WithDisclosableClaim(name string, value any) *Builder {
	b.disclosableClaims[name] = value
	return b
}

// WithExpiry sets the credential's expiry ("exp" claim).
func (b *Builder) WithExpiry(expiry time.Time) *Builder {
	b.expiry = expiry
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

// WithIssuer sets the credential's issuer ("iss" claim).
func (b *Builder) WithIssuer(issuer string) *Builder {
	b.issuer = issuer
	return b
}

// WithSubject sets the credential's subject ("sub" claim).
func (b *Builder) WithSubject(subject string) *Builder {
	b.subject = subject
	return b
}

// Build signs b's claims and returns the compact SD-JWT VC serialization:
// the signed JWT, followed by one "~"-separated disclosure per
// WithDisclosableClaim call, in Go's map-iteration order — itself
// randomized per run, which happens to satisfy the spec's recommendation
// against a fixed, information-leaking digest order.
func (b *Builder) Build() (string, error) {

	// turn disclosable claims into disclosures and their digests
	digests := make([]string, 0, len(b.disclosableClaims))
	disclosures := make([]string, 0, len(b.disclosableClaims))
	for name, value := range b.disclosableClaims {
		d, err := newDisclosure(name, value)
		if err != nil {
			return "", err
		}
		digests = append(digests, d.digest)
		disclosures = append(disclosures, d.encoded)
	}

	// assemble the signed JWT body
	claims := map[string]any{
		"vct": b.vct,
		"iat": time.Now().Unix(),
	}
	for name, value := range b.claims {
		claims[name] = value
	}
	if b.issuer != "" {
		claims["iss"] = b.issuer
	}
	if b.subject != "" {
		claims["sub"] = b.subject
	}
	if !b.expiry.IsZero() {
		claims["exp"] = b.expiry.Unix()
	}
	if b.holderKey != nil {
		claims["cnf"] = map[string]any{"jwk": b.holderKey}
	}
	if len(digests) > 0 {
		claims["_sd"] = digests
		claims["_sd_alg"] = sdAlgSha256
	}

	// sign and append disclosures
	signedJwt, err := jwt.Signed(b.signer).Claims(claims).Serialize()
	if err != nil {
		return "", fmt.Errorf("sdjwt: sign: %w", err)
	}

	var sb strings.Builder
	sb.WriteString(signedJwt)
	for _, d := range disclosures {
		sb.WriteString("~")
		sb.WriteString(d)
	}
	sb.WriteString("~")
	return sb.String(), nil
}

// Private ---------------------------------------------------------------------------------------------------------------

// disclosure is one selectively-disclosable claim: a salted, base64url-encoded
// JSON array disclosing name and value, and that encoding's SHA-256 digest
// naming it in a signed JWT's "_sd" claim without revealing it.
type disclosure struct {
	encoded string
	digest  string
}

// newDisclosure builds a disclosure for name/value, generating a fresh
// 128-bit salt per the SD-JWT spec's minimum entropy recommendation.
func newDisclosure(name string, value any) (disclosure, error) {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return disclosure{}, fmt.Errorf("sdjwt: generate disclosure salt: %w", err)
	}

	data, err := json.Marshal([]any{base64.RawURLEncoding.EncodeToString(salt), name, value})
	if err != nil {
		return disclosure{}, fmt.Errorf("sdjwt: marshal disclosure: %w", err)
	}
	encoded := base64.RawURLEncoding.EncodeToString(data)

	sum := sha256.Sum256([]byte(encoded))
	return disclosure{encoded: encoded, digest: base64.RawURLEncoding.EncodeToString(sum[:])}, nil
}
