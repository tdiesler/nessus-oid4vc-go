package main

import (
	"github.com/spf13/cobra"
	co "github.com/tdiesler/nessus-oid4vc-go/pkg/common"
	"github.com/tdiesler/nessus-oid4vc-go/pkg/holder"
)

// RootOpts ================================================================================================================

// RootOpts holds flags shared by every subcommand — each subcommand embeds
// it and registers its fields as its own local flags via bindRootOpts,
// rather than this being threaded through command constructors.
type RootOpts struct {
	Issuer string
}

// NewRootCmd builds the oid4vc command tree. With no subcommand it displays help.
func NewRootCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "oid4vc",
		Short: "OID4VC Wallet CLI",
	}
	cmd.AddCommand(
		NewLoginCmd(),
		NewLogoutCmd(),
		NewKeyCmd(),
		NewVcCmd())
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

// ensureDefaultVaultIssuer adds a vault-flavored Issuer to state, derived
// from this project's own AppConfig, unless one is already present.
func ensureDefaultVaultIssuer() error {

	state, err := holder.LoadWalletState()
	if err != nil {
		return err
	}

	if _, ok := state.Issuers[holder.IssuerVault]; ok {
		return nil
	}

	cfg, err := co.GetAppConfig()
	if err != nil {
		return err
	}

	issuer := holder.NewIssuer(holder.IssuerVault, "http://"+cfg.Oid4vciAddr)
	issuer.RedirectUri = cfg.RedirectUri
	issuer.DefaultClient = cfg.OidcClient
	issuer.DefaultUser = co.UserAlice
	issuer.Users[co.UserAlice] = holder.NewConnection(cfg.OidcClient)

	state.Issuers[holder.IssuerVault] = issuer
	if state.DefaultIssuer == "" {
		state.DefaultIssuer = holder.IssuerVault
	}
	return nil
}
