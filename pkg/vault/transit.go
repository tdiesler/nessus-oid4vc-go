package vault

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"strconv"
	"strings"
)

// TransitAccessor ===============================================================================================

// TransitAccessor accesses Vault's transit secrets engine for issuer-side
// signing: the issuer service never holds a private key itself, it only
// ever asks Vault to sign on its behalf.
type TransitAccessor struct {
}

// NewTransitAccessor constructs a TransitAccessor.
func NewTransitAccessor() *TransitAccessor {
	return &TransitAccessor{}
}

// PublicKey reads keyName's current public key from Vault's transit engine.
func (s *TransitAccessor) PublicKey(keyName string) (*ecdsa.PublicKey, error) {
	client, err := RootClient()
	if err != nil {
		return nil, err
	}

	secret, err := client.Logical().Read("transit/keys/" + keyName)
	if err != nil {
		return nil, fmt.Errorf("read transit key %q: %w", keyName, err)
	}
	if secret == nil {
		return nil, fmt.Errorf("transit key %q not found", keyName)
	}

	version, err := latestKeyVersion(secret.Data)
	if err != nil {
		return nil, fmt.Errorf("transit key %q: %w", keyName, err)
	}

	versions, ok := secret.Data["keys"].(map[string]any)
	if !ok {
		return nil, fmt.Errorf("transit key %q: no key versions", keyName)
	}
	versionData, ok := versions[version].(map[string]any)
	if !ok {
		return nil, fmt.Errorf("transit key %q: version %s not found", keyName, version)
	}
	pemKey, ok := versionData["public_key"].(string)
	if !ok || pemKey == "" {
		return nil, fmt.Errorf("transit key %q: no public key in version %s", keyName, version)
	}

	block, _ := pem.Decode([]byte(pemKey))
	if block == nil {
		return nil, fmt.Errorf("transit key %q: decode PEM public key: no block found", keyName)
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("transit key %q: parse public key: %w", keyName, err)
	}
	ecKey, ok := pub.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("transit key %q: not an ECDSA public key", keyName)
	}
	return ecKey, nil
}

// Sign signs message with keyName's current signing key, returning the raw
// (non-ASN.1) signature bytes that JWS expects for ECDSA algorithms (RFC
// 7518 §3.4) — Vault's "jws" marshaling mode produces exactly that layout,
// so the result can be used as a JWS signature value with no reformatting.
func (s *TransitAccessor) Sign(keyName string, message []byte) ([]byte, error) {
	client, err := RootClient()
	if err != nil {
		return nil, err
	}

	secret, err := client.Logical().Write("transit/sign/"+keyName, map[string]any{
		"input":                base64.StdEncoding.EncodeToString(message),
		"marshaling_algorithm": "jws",
	})
	if err != nil {
		return nil, fmt.Errorf("sign with transit key %q: %w", keyName, err)
	}
	if secret == nil {
		return nil, fmt.Errorf("sign with transit key %q: no response", keyName)
	}

	sig, ok := secret.Data["signature"].(string)
	if !ok || sig == "" {
		return nil, fmt.Errorf("sign with transit key %q: no signature in response", keyName)
	}

	const prefix = "vault:v1:"
	if !strings.HasPrefix(sig, prefix) {
		return nil, fmt.Errorf("sign with transit key %q: unexpected signature format %q", keyName, sig)
	}

	// "jws" marshaling encodes the signature with base64url, matching JWS's
	// own compact-serialization encoding, rather than Vault's usual
	// standard-base64 envelope.
	encoded := strings.TrimPrefix(sig, prefix)
	return base64.RawURLEncoding.DecodeString(encoded)
}

// Private -------------------------------------------------------------------------------------------------------------

// latestKeyVersion extracts "latest_version" from a transit/keys/<name>
// read response, tolerating either JSON number representation the Vault
// client may hand back.
func latestKeyVersion(data map[string]any) (string, error) {
	v, ok := data["latest_version"]
	if !ok {
		return "", fmt.Errorf("no latest_version in response")
	}
	switch n := v.(type) {
	case float64:
		return strconv.FormatFloat(n, 'f', 0, 64), nil
	case json.Number:
		return n.String(), nil
	case string:
		return n, nil
	default:
		return "", fmt.Errorf("unexpected latest_version type %T", v)
	}
}
