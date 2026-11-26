package oid4vci

import (
	"encoding/json"
	"html/template"
	"net/http"
	"net/url"
	"strings"

	co "github.com/tdiesler/nessus-oid4vc-go/pkg/common"
)

// NewMux builds this authorization server's HTTP route table: discovery,
// the Authorization Code flow's /authorize and /token endpoints, /userinfo,
// /revoke, and the JWKS document /token's id_tokens verify against. This
// file holds every HTTP-specific concern (routes, request/response
// encoding), kept separate from CredentialIssuer's own protocol logic.
func NewMux(ci *CredentialIssuer) *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /.well-known/openid-configuration", handleDiscovery(ci))
	mux.HandleFunc("GET /.well-known/openid-credential-issuer", handleCredentialIssuerMetadata(ci))
	mux.HandleFunc("GET /authorize", handleAuthorizeForm(ci))
	mux.HandleFunc("POST /authorize", handleAuthorizeLogin(ci))
	mux.HandleFunc("POST /token", handleToken(ci))
	mux.HandleFunc("POST /nonce", handleNonce(ci))
	mux.HandleFunc("POST /credential", handleCredential(ci))
	mux.HandleFunc("POST /revoke", handleRevoke(ci))
	mux.HandleFunc("GET /userinfo", handleUserInfo(ci))
	mux.HandleFunc("GET /jwks.json", handleJWKS(ci))
	return mux
}

// Functions ---------------------------------------------------------------------------------------------------------

// loginFormTemplate renders a minimal userpass login form: client_id,
// redirect_uri and state are threaded through as hidden fields rather than
// server-side session state, since there's nothing sensitive in them that
// the holder's own user-agent didn't already supply in the GET request.
var loginFormTemplate = template.Must(template.New("login").Parse(`<!DOCTYPE html>
<html>
<body>
<form method="POST" action="/authorize">
<input type="hidden" name="client_id" value="{{.ClientId}}">
<input type="hidden" name="redirect_uri" value="{{.RedirectUri}}">
<input type="hidden" name="scope" value="{{.Scope}}">
<input type="hidden" name="state" value="{{.State}}">
<input name="username" placeholder="Username" autocomplete="username">
<input name="password" type="password" placeholder="Password" autocomplete="current-password">
<button type="submit">Login</button>
</form>
</body>
</html>
`))

type loginFormData struct {
	ClientId    string
	RedirectUri string
	Scope       string
	State       string
}

func handleAuthorizeForm(ci *CredentialIssuer) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		clientId, redirectUri, responseType := q.Get("client_id"), q.Get("redirect_uri"), q.Get("response_type")

		if err := ci.ValidateAuthorizationRequest(clientId, redirectUri, responseType); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		data := loginFormData{ClientId: clientId, RedirectUri: redirectUri, Scope: q.Get("scope"), State: q.Get("state")}
		_ = loginFormTemplate.Execute(w, data)
	}
}

func handleAuthorizeLogin(ci *CredentialIssuer) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		clientId, redirectUri, scope, state := r.FormValue("client_id"), r.FormValue("redirect_uri"), r.FormValue("scope"), r.FormValue("state")

		code, err := ci.CompleteLogin(clientId, redirectUri, scope, r.FormValue("username"), r.FormValue("password"))
		if err != nil {
			http.Error(w, err.Error(), http.StatusUnauthorized)
			return
		}

		callback, err := url.Parse(redirectUri)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		q := callback.Query()
		q.Set("code", code)
		if state != "" {
			q.Set("state", state)
		}
		callback.RawQuery = q.Encode()

		http.Redirect(w, r, callback.String(), http.StatusFound)
	}
}

// credentialRequest is the OID4VCI Credential Request body this endpoint
// accepts: a single proof naming a credential_identifier (from
// authorization_details). credential_configuration_id requests aren't
// supported — the holder CLI only ever sends credential_identifier.
type credentialRequest struct {
	CredentialIdentifier string `json:"credential_identifier"`
	Proofs               struct {
		Jwt []string `json:"jwt"`
	} `json:"proofs"`
}

// credentialResponse is the OID4VCI Credential Response body.
type credentialResponse struct {
	Credentials []credentialResponseEntry `json:"credentials"`
}

type credentialResponseEntry struct {
	Credential string `json:"credential"`
}

// nonceResponse is the OID4VCI Nonce Response body.
type nonceResponse struct {
	CNonce string `json:"c_nonce"`
}

func handleCredential(ci *CredentialIssuer) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		const prefix = "Bearer "
		auth := r.Header.Get("Authorization")
		if !strings.HasPrefix(auth, prefix) {
			http.Error(w, "missing bearer token", http.StatusUnauthorized)
			return
		}

		var req credentialRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if len(req.Proofs.Jwt) != 1 {
			http.Error(w, "exactly one jwt proof is required", http.StatusBadRequest)
			return
		}

		credential, err := ci.IssueCredential(strings.TrimPrefix(auth, prefix), req.CredentialIdentifier, req.Proofs.Jwt[0])
		if err != nil {
			http.Error(w, err.Error(), http.StatusUnauthorized)
			return
		}

		writeJSON(w, http.StatusOK, credentialResponse{Credentials: []credentialResponseEntry{{Credential: credential}}})
	}
}

func handleCredentialIssuerMetadata(ci *CredentialIssuer) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, co.NewCredentialIssuerMetadata(ci.Issuer, ci.cfg))
	}
}

func handleDiscovery(ci *CredentialIssuer) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, NewMetadata(ci.Issuer, ci.cfg))
	}
}

func handleJWKS(ci *CredentialIssuer) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, ci.signer.JWKS())
	}
}

func handleNonce(ci *CredentialIssuer) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		nonce, err := ci.IssueNonce()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		writeJSON(w, http.StatusOK, nonceResponse{CNonce: nonce})
	}
}

// handleRevoke implements RFC 7009 token revocation: always a 200,
// whether or not token was valid/known, to avoid leaking which tokens are
// live.
func handleRevoke(ci *CredentialIssuer) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		_ = ci.Logout(r.FormValue("token"))
		w.WriteHeader(http.StatusOK)
	}
}

func handleToken(ci *CredentialIssuer) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		token, err := ci.ExchangeCode(r.FormValue("code"), r.FormValue("client_id"), r.FormValue("redirect_uri"))
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		writeJSON(w, http.StatusOK, token)
	}
}

func handleUserInfo(ci *CredentialIssuer) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		const prefix = "Bearer "
		auth := r.Header.Get("Authorization")
		if !strings.HasPrefix(auth, prefix) {
			http.Error(w, "missing bearer token", http.StatusUnauthorized)
			return
		}

		claims, err := ci.ReadSubjectsKeyValueClaims(strings.TrimPrefix(auth, prefix))
		if err != nil {
			http.Error(w, err.Error(), http.StatusUnauthorized)
			return
		}

		writeJSON(w, http.StatusOK, claims)
	}
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
