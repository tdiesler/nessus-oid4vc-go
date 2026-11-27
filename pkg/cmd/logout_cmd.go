package cmd

import (
	"github.com/spf13/cobra"
	co "github.com/tdiesler/nessus-oid4vc-go/pkg/common"
	"github.com/tdiesler/nessus-oid4vc-go/pkg/holder"
)

// LogoutOpts ==============================================================================================================

// LogoutOpts holds logout's flag values. It embeds RootOpts for Issuer,
// shared with every subcommand.
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
	w, err := holder.NewWallet(o.Issuer, o.User)
	if err != nil {
		return err
	}

	iss := w.Issuer().Alias
	ok, err := w.Logout()
	if err != nil {
		return err
	}
	if !ok {
		co.InfoF("No active session for %q with issuer %q\n", w.Username(), iss)
		return nil
	}

	co.InfoF("Logged out %q from issuer %q\n", w.Username(), iss)
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
	_ = cmd.RegisterFlagCompletionFunc("user", completeUsername)
	return cmd
}
