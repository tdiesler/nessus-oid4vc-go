package cmd

import (
	"github.com/spf13/cobra"
)

// rootShort is oid4vc's one-line description, shared between NewRootCmd's
// own Short text and the REPL's startup banner (see ReplOpts.Run).
const rootShort = "OID4VC Wallet CLI and Issuer using Hashicorp Vault"

// RootOpts ================================================================================================================

// RootOpts holds flags shared by every subcommand — each subcommand embeds
// it and registers its fields as its own local flags via bindRootOpts,
// rather than this being threaded through command constructors.
type RootOpts struct {
	Issuer string
}

// NewRootCmd builds the oid4vc command tree: wallet operations against an
// issuer, plus run-server to run the oid4vci AuthorizationServer itself.
// With no subcommand it enters the interactive REPL (see NewReplCmd).
func NewRootCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "oid4vc",
		Short: rootShort,
		RunE: func(cmd *cobra.Command, args []string) error {
			return NewReplOpts().Run()
		},
		CompletionOptions: cobra.CompletionOptions{DisableDefaultCmd: true},
	}
	cmd.AddCommand(
		NewLoginCmd(),
		NewLogoutCmd(),
		NewKeyCmd(),
		NewRunServerCmd(),
		NewShowCmd(),
		NewSwitchCmd(),
		NewVcCmd(),
		NewReplCmd())
	return cmd
}

// Functions ---------------------------------------------------------------------------------------------------------

// bindRootOpts registers the --issuer flag RootOpts holds on cmd, bound
// directly to root.Issuer. Called from each NewXCmd at command-construction
// time, alongside that command's own flags — not from RunE, since cobra
// parses a command's flags before RunE runs.
func bindRootOpts(cmd *cobra.Command, root *RootOpts) {
	cmd.Flags().StringVar(&root.Issuer, "issuer", "", "Issuer alias to operate against (default: the holder's default issuer)")
}
