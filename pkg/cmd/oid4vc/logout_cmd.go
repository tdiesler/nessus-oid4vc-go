package main

import (
	"fmt"

	"github.com/spf13/cobra"
	"github.com/tdiesler/nessus-oid4vc-go/pkg/wallet"
)

// LogoutOpts ==============================================================================================================

// LogoutOpts holds logout's flag values — exported so tests can construct
// one directly and call Run, instead of driving the cobra command through
// its flags. It embeds RootOpts for Issuer, shared with every subcommand.
type LogoutOpts struct {
	RootOpts
	User string
}

// NewLogoutOpts constructs a LogoutOpts.
func NewLogoutOpts() *LogoutOpts {
	return &LogoutOpts{}
}

// Run ends o.User's session against o.Issuer.
func (o *LogoutOpts) Run() error {
	state, alias, issuer, err := resolveIssuer(o.Issuer)
	if err != nil {
		return err
	}

	username := o.User
	if username == "" {
		username = issuer.DefaultUser
	}
	if username == "" {
		return fmt.Errorf("no user specified and issuer %q has no default user", alias)
	}

	conn, ok := issuer.Users[username]
	if !ok || conn.Token == nil {
		fmt.Printf("No active session for %q against issuer %q\n", username, alias)
		return nil
	}

	metadata, err := wallet.DiscoverMetadata(issuer.IssuerURL)
	if err != nil {
		return err
	}
	switch {
	case metadata.EndSessionEndpoint != "":
		err = wallet.EndSession(metadata.EndSessionEndpoint, conn.ClientId, conn.Token)
	case metadata.RevocationEndpoint != "":
		err = wallet.RevokeToken(metadata.RevocationEndpoint, conn.ClientId, conn.Token.AccessToken)
	}
	if err != nil {
		return err
	}

	conn.Token = nil
	if err := state.SaveWalletState(issuer.Flavor); err != nil {
		return err
	}

	fmt.Printf("Logged out %q from issuer %q\n", username, alias)
	return nil
}

// NewLogoutCmd builds the logout command.
func NewLogoutCmd() *cobra.Command {
	opts := NewLogoutOpts()
	cmd := &cobra.Command{
		Use:   "logout",
		Short: "End an issuer's user session",
		RunE: func(cmd *cobra.Command, args []string) error {
			return opts.Run()
		},
	}
	bindRootOpts(cmd, &opts.RootOpts)
	cmd.Flags().StringVar(&opts.User, "user", "", "Username to log out (default: the issuer's default user)")
	return cmd
}
