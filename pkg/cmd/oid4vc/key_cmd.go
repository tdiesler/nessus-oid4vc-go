package main

import (
	"fmt"

	"github.com/spf13/cobra"
	"github.com/tdiesler/nessus-oid4vc-go/pkg/wallet"
)

// NewKeyCmd builds the key command, grouping key management operations.
// With no subcommand it displays help.
func NewKeyCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "key",
		Short: "Manage holder keys",
	}
	cmd.AddCommand(NewKeyCreateCmd())
	return cmd
}

// KeyCreateOpts ===========================================================================================================

// KeyCreateOpts holds key create's flag values — exported so tests can
// construct one directly and call Run, instead of driving the cobra
// command through its flags. It embeds RootOpts for Issuer, shared with
// every subcommand.
type KeyCreateOpts struct {
	RootOpts
	Name string
	User string
}

// NewKeyCreateOpts constructs a KeyCreateOpts.
func NewKeyCreateOpts() *KeyCreateOpts {
	return &KeyCreateOpts{}
}

// Run generates an ES256 holder key for o.User against o.Issuer, named
// o.Name if given, or auto-derived otherwise.
func (o *KeyCreateOpts) Run() error {
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
	if !ok {
		conn = wallet.NewConnection(issuer.DefaultClient)
		issuer.Users[username] = conn
	}

	kid, err := conn.AddHolderKey(o.Name)
	if err != nil {
		return err
	}

	if err := state.SaveWalletState(issuer.Flavor); err != nil {
		return err
	}

	fmt.Printf("Created ES256 holder key %q for %q against issuer %q\n", kid, username, alias)
	return nil
}

// NewKeyCreateCmd builds the key create command.
func NewKeyCreateCmd() *cobra.Command {
	opts := NewKeyCreateOpts()
	cmd := &cobra.Command{
		Use:   "create",
		Short: "Create a holder key",
		RunE: func(cmd *cobra.Command, args []string) error {
			return opts.Run()
		},
	}
	bindRootOpts(cmd, &opts.RootOpts)
	cmd.Flags().StringVar(&opts.Name, "name", "", "Key name (auto-derived if not given)")
	cmd.Flags().StringVar(&opts.User, "user", "", "Target user (default: the issuer's default user)")
	return cmd
}
