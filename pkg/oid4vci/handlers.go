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
// /revoke, and the JWKS document /token's id_tokens verify against. This is
// the only file in the package that knows about net/http — a future Vault
// plugin would replace just this file with logical.Backend paths, calling
// the same AuthorizationServer underneath.
func NewMux(as *AuthorizationServer) *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /.well-known/openid-configuration", handleDiscovery(as))
	mux.HandleFunc("GET /.well-known/openid-credential-issuer", handleCredentialIssuerMetadata(as))
	mux.HandleFunc("GET /authorize", handleAuthorizeForm(as))
	mux.HandleFunc("POST /authorize", handleAuthorizeLogin(as))
	mux.HandleFunc("POST /token", handleToken(as))
	mux.HandleFunc("POST /revoke", handleRevoke(as))
	mux.HandleFunc("GET /userinfo", handleUserInfo(as))
	mux.HandleFunc("GET /jwks.json", handleJWKS(as))
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
	State       string
}

func handleAuthorizeForm(as *AuthorizationServer) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		clientId, redirectUri, responseType := q.Get("client_id"), q.Get("redirect_uri"), q.Get("response_type")

		if err := as.ValidateAuthorizationRequest(clientId, redirectUri, responseType); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_ = loginFormTemplate.Execute(w, loginFormData{ClientId: clientId, RedirectUri: redirectUri, State: q.Get("state")})
	}
}

func handleAuthorizeLogin(as *AuthorizationServer) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		clientId, redirectUri, state := r.FormValue("client_id"), r.FormValue("redirect_uri"), r.FormValue("state")

		code, err := as.CompleteLogin(clientId, redirectUri, r.FormValue("username"), r.FormValue("password"))
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

func handleCredentialIssuerMetadata(as *AuthorizationServer) http.HandlerFunc {
	metadata := co.NewCredentialIssuerMetadata(as.Issuer, as.cfg)
	return func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, metadata)
	}
}

func handleDiscovery(as *AuthorizationServer) http.HandlerFunc {
	metadata := NewMetadata(as.Issuer, as.cfg)
	return func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, metadata)
	}
}

func handleJWKS(as *AuthorizationServer) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, as.signer.JWKS())
	}
}

// handleRevoke implements RFC 7009 token revocation: always a 200,
// whether or not token was valid/known, to avoid leaking which tokens are
// live.
func handleRevoke(as *AuthorizationServer) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		_ = as.Logout(r.FormValue("token"))
		w.WriteHeader(http.StatusOK)
	}
}

func handleToken(as *AuthorizationServer) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		token, err := as.ExchangeCode(r.FormValue("code"), r.FormValue("client_id"), r.FormValue("redirect_uri"))
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		writeJSON(w, http.StatusOK, token)
	}
}

func handleUserInfo(as *AuthorizationServer) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		const prefix = "Bearer "
		auth := r.Header.Get("Authorization")
		if !strings.HasPrefix(auth, prefix) {
			http.Error(w, "missing bearer token", http.StatusUnauthorized)
			return
		}

		claims, err := as.ReadSubjectsKeyValueClaims(strings.TrimPrefix(auth, prefix))
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
