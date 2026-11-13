package oauth

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"time"

	"github.com/chromedp/chromedp"
	log "github.com/tdiesler/nessus-oid4vc-go/pkg/logging"
)

// BrowserAuthorizer completes an OAuth 2.0 OAuthAuthorizationRequest the way a
// user-agent would — interactively, through whatever login page the
// authorization server presents.
// Returns an authorization code on success.
type BrowserAuthorizer interface {
	Authorize(req *OAuthAuthorizationRequest, username, password string) (string, error)
}

var _ BrowserAuthorizer = (*ChromeAuthorizer)(nil)

// ChromeAuthorizer is a BrowserAuthorizer backed by chromedp.
type ChromeAuthorizer struct {
}

// NewChromeAuthorizer constructs a ChromeAuthorizer.
func NewChromeAuthorizer() (*ChromeAuthorizer, error) {
	return &ChromeAuthorizer{}, nil
}

// Authorize drives Vault's own OIDC provider login page in a real browser.
//
// Vault's /authorize API rejects unauthenticated requests outright (no
// server-side HTML login page); its bundled UI is what shows a login form
// and performs the userpass login before continuing the authorize flow. So
// this drives that UI rather than calling the API directly.
func (c *ChromeAuthorizer) Authorize(req *OAuthAuthorizationRequest, username, password string) (string, error) {
	redirectURI, err := url.Parse(req.RedirectUri)
	if err != nil {
		return "", fmt.Errorf("parse redirect_uri %q: %w", req.RedirectUri, err)
	}

	codeCh := make(chan string, 1)
	errCh := make(chan error, 1)
	srv := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if msg := r.URL.Query().Get("error"); msg != "" {
				errCh <- fmt.Errorf("authorize callback error: %s", msg)
			} else {
				codeCh <- r.URL.Query().Get("code")
			}
			if _, err := fmt.Fprintln(w, "ok"); err != nil {
				log.ErrorE(err)
			}
		}),
	}
	ln, err := net.Listen("tcp", redirectURI.Host)
	if err != nil {
		return "", fmt.Errorf("listen on %s for authorize callback: %w", redirectURI.Host, err)
	}
	go func() { _ = srv.Serve(ln) }()
	defer func() { _ = srv.Close() }()

	allocOpts := chromedp.DefaultExecAllocatorOptions[:]
	if path := chromeExecPath(); path != "" {
		allocOpts = append(allocOpts, chromedp.ExecPath(path))
	}
	actx, cancel := chromedp.NewExecAllocator(context.Background(), allocOpts...)
	defer cancel()
	ctx, cancel := chromedp.NewContext(actx)
	defer cancel()
	ctx, cancel = context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	// Vault's login form defaults to the "Token" auth method; switch it to "Userpass"
	const selectUserpassJS = `(() => {
		const sel = document.querySelector('select[name="selectedAuthMethod"]');
		sel.value = 'userpass';
		sel.dispatchEvent(new Event('input', {bubbles: true}));
		sel.dispatchEvent(new Event('change', {bubbles: true}));
	})()`

	if err := chromedp.Do(ctx,
		chromedp.Navigate(req.ToRequestUrl()),
		chromedp.WaitVisible(chromedp.CSS(`select[name="selectedAuthMethod"]`)),
	); err != nil {
		return "", fmt.Errorf("load Vault login page: %w", err)
	}
	if _, err := chromedp.Run(ctx, chromedp.Evaluate[any](selectUserpassJS)); err != nil {
		return "", fmt.Errorf("select userpass auth method: %w", err)
	}
	if err := chromedp.Do(ctx,
		chromedp.WaitVisible(chromedp.CSS(`input[name="username"]`)),
		chromedp.SendKeys(chromedp.CSS(`input[name="username"]`), username),
		chromedp.SendKeys(chromedp.CSS(`input[name="password"]`), password),
		chromedp.Click(chromedp.CSS(`button[type="submit"]`)),
	); err != nil {
		return "", fmt.Errorf("submit Vault login form: %w", err)
	}

	select {
	case code := <-codeCh:
		return code, nil
	case err := <-errCh:
		return "", err
	case <-ctx.Done():
		return "", fmt.Errorf("timed out waiting for authorize callback: %w", ctx.Err())
	}
}

// chromeExecPath returns the path to a Chromium-based browser binary.
func chromeExecPath() string {
	if p := os.Getenv("CHROME_BIN"); p != "" {
		return p
	}
	candidates := []string{
		"/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
		"/Applications/Chromium.app/Contents/MacOS/Chromium",
		"/Applications/Brave Browser.app/Contents/MacOS/Brave Browser",
	}
	for _, c := range candidates {
		if _, err := os.Stat(c); err == nil {
			return c
		}
	}
	return ""
}
