package cmd

import (
	"github.com/spf13/cobra"
	co "github.com/tdiesler/nessus-oid4vc-go/pkg/common"
	"github.com/tdiesler/nessus-oid4vc-go/pkg/holder"
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

// KeyCreateOpts holds key create's flag values. It embeds RootOpts for
// Issuer, shared with every subcommand.
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
	w, err := holder.NewWallet(o.Issuer, o.User)
	if err != nil {
		return err
	}

	kid, err := w.CreateKey(o.Name)
	if err != nil {
		return err
	}

	iss := w.Issuer().Alias
	co.InfoF("Created ES256 holder key %q for %q with issuer %q\n", kid, w.Username(), iss)
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
	_ = cmd.RegisterFlagCompletionFunc("user", completeUsername)
	return cmd
}
