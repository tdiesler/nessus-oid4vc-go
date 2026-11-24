package holder

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"

	"github.com/chromedp/chromedp"
	co "github.com/tdiesler/nessus-oid4vc-go/pkg/common"
)

// BrowserLogin ===========================================================================================================

// BrowserLogin drives the user-agent side of an OAuth 2.0 Authorization
// Code request against a standard username/password HTML login form:
// either headlessly, filling in the form via chromedp, or interactively, by
// opening the system browser and letting the user complete it themselves.
// Either way, the resulting code comes back over the same local HTTP
// listener bound to RedirectUri, which must already be a registered
// redirect URI on the client — not urn:ietf:wg:oauth:2.0:oob.
type BrowserLogin struct {
	AuthorizationEndpoint string
	ClientId              string
	RedirectUri           string
	Scope                 string
}

// NewBrowserLogin constructs a BrowserLogin against authorizationEndpoint.
func NewBrowserLogin(authorizationEndpoint, clientId, redirectUri, scope string) *BrowserLogin {
	return &BrowserLogin{
		AuthorizationEndpoint: authorizationEndpoint,
		ClientId:              clientId,
		RedirectUri:           redirectUri,
		Scope:                 scope,
	}
}

// Headless completes the request without user interaction, filling in the
// login form in a headless Chromium via chromedp.
func (b *BrowserLogin) Headless(username, password string) (string, error) {
	listener, err := newCallbackListener(b.RedirectUri)
	if err != nil {
		return "", err
	}
	defer listener.Close()

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

	const usernameField = `input[name="username"]`
	const passwordField = `input[name="password"]`
	const submitControl = `button[type="submit"], input[type="submit"]`

	if err := chromedp.Do(ctx, chromedp.Navigate(b.authorizeUrl())); err != nil {
		return "", fmt.Errorf("load login page: %w", err)
	}

	// The authorization server can reject the request itself (e.g. a
	// policy denying the requested scope) and show an error page instead
	// of a login form — give the form a short window to appear rather
	// than waiting out the full callback timeout for a field that's never
	// coming, and surface what the page actually says instead.
	formCtx, cancelForm := context.WithTimeout(ctx, 5*time.Second)
	defer cancelForm()
	if err := chromedp.Do(formCtx, chromedp.WaitVisible(chromedp.CSS(usernameField))); err != nil {
		text, _ := chromedp.Run(ctx, chromedp.Text("body"))
		return "", fmt.Errorf("login form did not appear: %s", strings.TrimSpace(text))
	}

	if err := chromedp.Do(ctx,
		chromedp.SendKeys(chromedp.CSS(usernameField), username),
		chromedp.SendKeys(chromedp.CSS(passwordField), password),
		chromedp.Click(chromedp.CSS(submitControl)),
	); err != nil {
		return "", fmt.Errorf("drive login form: %w", err)
	}

	return listener.Await(ctx)
}

// Interactive completes the request by opening the system's default
// browser and waiting for the user to log in themselves.
func (b *BrowserLogin) Interactive() (string, error) {
	listener, err := newCallbackListener(b.RedirectUri)
	if err != nil {
		return "", err
	}
	defer listener.Close()

	authUrl := b.authorizeUrl()
	if err := openSystemBrowser(authUrl); err != nil {
		fmt.Println("Open this URL in your browser to log in:")
		fmt.Println(authUrl)
	} else {
		fmt.Println("Opening browser for login...")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	return listener.Await(ctx)
}

// Private -------------------------------------------------------------------------------------------------------------

// authorizeUrl renders b as the URL a user-agent is sent to.
func (b *BrowserLogin) authorizeUrl() string {
	q := url.Values{}
	q.Set("response_type", "code")
	q.Set("client_id", b.ClientId)
	q.Set("redirect_uri", b.RedirectUri)
	if b.Scope != "" {
		q.Set("scope", b.Scope)
	}
	return b.AuthorizationEndpoint + "?" + q.Encode()
}

// callbackListener is a short-lived local HTTP server bound to a
// redirect_uri's host:port, waiting for the single request that carries
// the authorization code, or an error.
type callbackListener struct {
	srv    *http.Server
	codeCh chan string
	errCh  chan error
}

// Await blocks until the callback carries a code, an error, or ctx is done.
func (c *callbackListener) Await(ctx context.Context) (string, error) {
	select {
	case code := <-c.codeCh:
		return code, nil
	case err := <-c.errCh:
		return "", err
	case <-ctx.Done():
		return "", fmt.Errorf("timed out waiting for authorize callback: %w", ctx.Err())
	}
}

// Close stops the listener.
func (c *callbackListener) Close() {
	_ = c.srv.Close()
}

// handle serves the redirect_uri callback itself.
func (c *callbackListener) handle(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	if msg := q.Get("error"); msg != "" {
		if desc := q.Get("error_description"); desc != "" {
			msg += ": " + desc
		}
		if _, err := fmt.Fprint(w, loginErrorPage(msg)); err != nil {
			co.ErrorE(err)
		}
		c.errCh <- fmt.Errorf("authorize callback error: %s", msg)
		return
	}
	if _, err := fmt.Fprint(w, loginSuccessPage); err != nil {
		co.ErrorE(err)
	}
	c.codeCh <- q.Get("code")
}

// Functions ---------------------------------------------------------------------------------------------------------

// loginSuccessPage and loginErrorPage are shown in the user-agent after
// the callback, whether that's a real browser (interactive mode) or
// chromedp's headless one (harmless there — nothing reads the response).
const loginSuccessPage = `<html><body><h2>Login successful</h2><p>You can close this tab.</p></body></html>`

func loginErrorPage(msg string) string {
	return fmt.Sprintf(`<html><body><h2>Login failed</h2><p>%s</p></body></html>`, msg)
}

// newCallbackListener starts a callbackListener bound to redirectUri's host:port.
func newCallbackListener(redirectUri string) (*callbackListener, error) {
	u, err := url.Parse(redirectUri)
	if err != nil {
		return nil, fmt.Errorf("parse redirect_uri %q: %w", redirectUri, err)
	}

	ln, err := net.Listen("tcp", u.Host)
	if err != nil {
		return nil, fmt.Errorf("listen on %s for authorize callback: %w", u.Host, err)
	}

	c := &callbackListener{
		codeCh: make(chan string, 1),
		errCh:  make(chan error, 1),
	}
	c.srv = &http.Server{Handler: http.HandlerFunc(c.handle)}
	go func() { _ = c.srv.Serve(ln) }()
	return c, nil
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

// openSystemBrowser opens targetUrl in the user's default browser.
func openSystemBrowser(targetUrl string) error {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		cmd = exec.Command("open", targetUrl)
	case "windows":
		cmd = exec.Command("cmd", "/c", "start", targetUrl)
	default:
		cmd = exec.Command("xdg-open", targetUrl)
	}
	return cmd.Start()
}
