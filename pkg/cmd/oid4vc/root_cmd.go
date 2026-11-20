package main

import (
	"fmt"

	"github.com/spf13/cobra"
	co "github.com/tdiesler/nessus-oid4vc-go/pkg/common"
	"github.com/tdiesler/nessus-oid4vc-go/pkg/wallet"
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
		Short: "Holder wallet CLI for OID4VCI issuers (Keycloak, Vault)",
	}
	cmd.AddCommand(NewLoginCmd(), NewLogoutCmd(), NewKeyCmd())
	return cmd
}

// Functions ---------------------------------------------------------------------------------------------------------

// bindRootOpts registers the --issuer flag RootOpts holds on cmd, bound
// directly to root.Issuer. Called from each NewXCmd at command-construction
// time, alongside that command's own flags — not from RunE, since cobra
// parses a command's flags before RunE runs.
func bindRootOpts(cmd *cobra.Command, root *RootOpts) {
	cmd.Flags().StringVar(&root.Issuer, "issuer", "", "Issuer alias to operate against (default: the wallet's default issuer)")
}

// ensureDefaultVaultIssuer adds a vault-flavored Issuer to state, derived
// from this project's own AppConfig, unless one is already present — the
// Vault-backed demo needs no separate setup step the way
// scripts/keycloak-setup's transform is for Keycloak, since everything it
// needs is already in config/oid4vc-config.yml. Its wallet alias is the
// same string as its IssuerFlavor, matching the convention
// scripts/keycloak-functions' transform also uses for the keycloak alias.
func ensureDefaultVaultIssuer(state *wallet.WalletState) error {
	alias := string(wallet.IssuerVault)
	if _, ok := state.Issuers[alias]; ok {
		return nil
	}

	cfg, err := co.GetAppConfig()
	if err != nil {
		return err
	}

	issuer := wallet.NewIssuer(wallet.IssuerVault, "http://"+cfg.Oid4vciAddr)
	issuer.RedirectUri = cfg.RedirectUri
	issuer.DefaultClient = cfg.OidcClient
	issuer.DefaultUser = co.UserAlice
	issuer.Users[co.UserAlice] = wallet.NewConnection(cfg.OidcClient)

	state.Issuers[alias] = issuer
	if state.DefaultIssuer == "" {
		state.DefaultIssuer = alias
	}
	return nil
}

// resolveIssuer loads the wallet state and returns it together with the
// named issuer — falling back to the wallet's DefaultIssuer when alias is
// empty — and the alias it was found under, so callers can mutate the
// issuer and save the WalletState back.
func resolveIssuer(alias string) (*wallet.WalletState, string, *wallet.Issuer, error) {

	state, err := wallet.LoadWalletState()
	if err != nil {
		return nil, "", nil, err
	}

	if err = ensureDefaultVaultIssuer(state); err != nil {
		return nil, "", nil, err
	}

	if alias == "" {
		alias = state.DefaultIssuer
	}
	if alias == "" {
		return nil, "", nil, fmt.Errorf("no issuer specified and no default issuer configured")
	}

	issuer, ok := state.Issuers[alias]
	if !ok {
		return nil, "", nil, fmt.Errorf("no issuer %q configured", alias)
	}
	return state, alias, issuer, nil
}
