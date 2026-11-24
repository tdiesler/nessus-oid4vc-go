package holder

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"

	co "github.com/tdiesler/nessus-oid4vc-go/pkg/common"
)

// Functions ---------------------------------------------------------------------------------------------------------

// buildProofJWT builds and signs an OID4VCI key-proof JWT: a short-lived
// JWT, typed "openid4vci-proof+jwt" and carrying holderKey's own public
// key in its header (go-jose derives it from holderKey when signing), that
// proves possession of holderKey and binds the request to cNonce.
func buildProofJWT(holderKey jose.JSONWebKey, clientId, issuerURL, cNonce string) (string, error) {
	opts := (&jose.SignerOptions{EmbedJWK: true}).WithType("openid4vci-proof+jwt")
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: holderKey.Key}, opts)
	if err != nil {
		return "", fmt.Errorf("build proof JWT signer: %w", err)
	}

	claims := jwt.Claims{
		Issuer:   clientId,
		Audience: jwt.Audience{issuerURL},
		IssuedAt: jwt.NewNumericDate(time.Now()),
	}
	proof, err := jwt.Signed(signer).Claims(claims).Claims(map[string]any{"nonce": cNonce}).Serialize()
	if err != nil {
		return "", fmt.Errorf("sign proof JWT: %w", err)
	}
	return proof, nil
}

// fetchCredential requests a credential from credentialEndpoint, naming it
// by credentialIdentifier if given, or credentialConfigurationId
// otherwise, proving possession of holderKey via a freshly built proof JWT
// bound to cNonce. Returns the issued credential string (a JWT or SD-JWT).
func fetchCredential(credentialEndpoint, accessToken, clientId, issuerURL, credentialIdentifier string, holderKey jose.JSONWebKey, cNonce string) (string, error) {
	proof, err := buildProofJWT(holderKey, clientId, issuerURL, cNonce)
	if err != nil {
		return "", err
	}

	reqBody := credentialRequest{
		CredentialIdentifier: credentialIdentifier,
	}
	reqBody.Proofs.Jwt = []string{proof}
	data, err := json.Marshal(reqBody)
	if err != nil {
		return "", fmt.Errorf("marshal credential request: %w", err)
	}

	req, err := http.NewRequest(http.MethodPost, credentialEndpoint, bytes.NewReader(data))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+accessToken)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("fetch credential: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("fetch credential: read response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("fetch credential: %s: %s", resp.Status, respBody)
	}

	var cred credentialResponse
	if err := json.Unmarshal(respBody, &cred); err != nil {
		return "", fmt.Errorf("fetch credential: decode response: %w", err)
	}
	if len(cred.Credentials) == 0 {
		return "", fmt.Errorf("fetch credential: no credentials in response")
	}
	return cred.Credentials[0].Credential, nil
}

// fetchNonce requests a fresh c_nonce from nonceEndpoint, authenticating
// with accessToken — required before each credential request, to bind the
// resulting proof JWT to this specific request (OID4VCI proof-of-possession).
func fetchNonce(nonceEndpoint, accessToken string) (string, error) {
	req := co.HttpPostRequest{Endpoint: nonceEndpoint}
	req.WithBearerAuth(accessToken)
	body, err := req.Post[nonceResponse](http.DefaultClient, url.Values{})
	if err != nil {
		return "", fmt.Errorf("fetch nonce: %w", err)
	}
	return body.CNonce, nil
}

// credentialRequest is the OID4VCI Credential Request body: a single proof
// naming either a specific credential_identifier (from
// authorization_details) or a credential_configuration_id.
type credentialRequest struct {
	CredentialIdentifier      string `json:"credential_identifier,omitempty"`
	CredentialConfigurationId string `json:"credential_configuration_id,omitempty"`
	Proofs                    struct {
		Jwt []string `json:"jwt"`
	} `json:"proofs"`
}

// credentialResponse is the OID4VCI Credential Response body.
type credentialResponse struct {
	Credentials []struct {
		Credential string `json:"credential"`
	} `json:"credentials"`
}

// nonceResponse is the OID4VCI Nonce Response body.
type nonceResponse struct {
	CNonce string `json:"c_nonce"`
}
