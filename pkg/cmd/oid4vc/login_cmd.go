package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/tdiesler/nessus-oid4vc-go/pkg/wallet"
	"golang.org/x/term"
)

// LoginOpts ===============================================================================================================

// LoginOpts holds login's flag values — exported so tests can construct one
// directly and call Run, instead of driving the cobra command through its
// flags.
type LoginOpts struct {
	Issuer   string
	Client   string
	User     string
	Password string
	Scope    string
	Browser  bool
}

// NewLoginOpts constructs a LoginOpts with Scope defaulted to "openid",
// matching the login command's own flag default.
func NewLoginOpts() *LoginOpts {
	return &LoginOpts{Scope: "openid"}
}

// Run authenticates as o.User against o.Issuer, storing the resulting
// session in the wallet.
func (o *LoginOpts) Run() error {
	state, alias, issuer, err := resolveIssuer(o.Issuer)
	if err != nil {
		return err
	}
	if issuer.RedirectUri == "" {
		return fmt.Errorf("issuer %q has no redirectUri configured", alias)
	}

	clientId := o.Client
	if clientId == "" {
		clientId = issuer.DefaultClient
	}
	if clientId == "" {
		return fmt.Errorf("no client specified and issuer %q has no default client", alias)
	}

	username := o.User
	if username == "" {
		username = issuer.DefaultUser
	}
	if username == "" {
		return fmt.Errorf("no user specified and issuer %q has no default user", alias)
	}

	password := o.Password
	if password == "" && !o.Browser {
		if !term.IsTerminal(int(os.Stdin.Fd())) {
			return fmt.Errorf("no console available for password input; use --password or --browser")
		}
		fmt.Print("Password: ")
		passwordBytes, err := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Println()
		if err != nil {
			return fmt.Errorf("read password: %w", err)
		}
		password = string(passwordBytes)
	}

	metadata, err := wallet.DiscoverMetadata(issuer.IssuerURL)
	if err != nil {
		return err
	}

	browserLogin := wallet.NewBrowserLogin(metadata.AuthorizationEndpoint, clientId, issuer.RedirectUri, o.Scope)
	var code string
	if o.Browser {
		code, err = browserLogin.Interactive()
	} else {
		code, err = browserLogin.Headless(username, password)
	}
	if err != nil {
		return err
	}

	token, authDetails, err := wallet.ExchangeAuthorizationCode(metadata.TokenEndpoint, clientId, code, issuer.RedirectUri)
	if err != nil {
		return err
	}

	conn, ok := issuer.Users[username]
	if !ok {
		conn = wallet.NewConnection(clientId)
		issuer.Users[username] = conn
	}
	conn.WithToken(token)
	if len(authDetails) > 0 {
		conn.AuthorizationDetails = authDetails
	}
	issuer.DefaultUser = username

	if err := state.SaveIssuer(walletDir, issuer.Flavor); err != nil {
		return err
	}

	fmt.Printf("Logged in as %q against issuer %q\n", username, alias)
	return nil
}

// NewLoginCmd builds the login command.
func NewLoginCmd() *cobra.Command {
	opts := NewLoginOpts()
	cmd := &cobra.Command{
		Use:   "login",
		Short: "Authenticate as an issuer's user",
		RunE: func(cmd *cobra.Command, args []string) error {
			return opts.Run()
		},
	}
	cmd.Flags().StringVar(&opts.Issuer, "issuer", "", "Issuer alias to log in against (default: the wallet's default issuer)")
	cmd.Flags().StringVar(&opts.Client, "client", "", "OAuth client ID (default: the issuer's default client)")
	cmd.Flags().StringVar(&opts.User, "user", "", "Username (default: the issuer's default user)")
	cmd.Flags().StringVar(&opts.Password, "password", "", "Password (prompted if not given, headless mode only)")
	cmd.Flags().StringVar(&opts.Scope, "scope", opts.Scope, "OAuth scope")
	cmd.Flags().BoolVar(&opts.Browser, "browser", false, "Open the system browser for login instead of driving it headlessly")
	return cmd
}
