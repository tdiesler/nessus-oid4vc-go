package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	co "github.com/tdiesler/nessus-oid4vc-go/pkg/common"
	"github.com/tdiesler/nessus-oid4vc-go/pkg/holder"
	"golang.org/x/term"
)

// LoginOpts ===============================================================================================================

// LoginOpts holds login's flag values. It embeds RootOpts for Issuer,
// shared with every subcommand.
type LoginOpts struct {
	RootOpts
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
// session in the holder.
func (o *LoginOpts) Run() error {
	if o.User == "" {
		return fmt.Errorf("--user is required")
	}

	w, err := holder.NewWallet(o.Issuer, o.User)
	if err != nil {
		return err
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

	if err = w.Login(o.Client, o.Scope, o.Browser, password); err != nil {
		return err
	}

	iss := w.Issuer().Alias
	co.InfoF("Logged in as %q with issuer %q\n", w.Username(), iss)
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
	bindRootOpts(cmd, &opts.RootOpts)
	cmd.Flags().StringVar(&opts.Client, "client", "", "OAuth client ID (default: the issuer's default client)")
	cmd.Flags().StringVar(&opts.User, "user", "", "Username (required)")
	cmd.Flags().StringVar(&opts.Password, "password", "", "Password (prompted if not given, headless mode only)")
	cmd.Flags().StringVar(&opts.Scope, "scope", opts.Scope, "OAuth scope")
	cmd.Flags().BoolVar(&opts.Browser, "browser", false, "Open the system browser for login instead of driving it headlessly")
	_ = cmd.RegisterFlagCompletionFunc("client", completeClientId)
	_ = cmd.RegisterFlagCompletionFunc("user", completeUsername)
	_ = cmd.RegisterFlagCompletionFunc("scope", completeScope)
	return cmd
}
