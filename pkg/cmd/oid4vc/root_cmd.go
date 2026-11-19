package main

import (
	"fmt"

	"github.com/spf13/cobra"
	co "github.com/tdiesler/nessus-oid4vc-go/pkg/common"
	"github.com/tdiesler/nessus-oid4vc-go/pkg/wallet"
)

// vaultIssuerAlias is the wallet alias ensureDefaultVaultIssuer uses.
const vaultIssuerAlias = "vault"

// walletDir is where the wallet CLI keeps its per-issuer-flavor state files
// (see pkg/wallet), relative to the current working directory — matching
// scripts/keycloak-setup's convention. A var, not a const, so tests can
// point it at a temp directory.
var walletDir = ".config"

// NewRootCmd builds the oid4vc command tree. With no subcommand it displays help.
func NewRootCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "oid4vc",
		Short: "Holder wallet CLI for OID4VCI issuers (Keycloak, Vault)",
	}
	cmd.AddCommand(NewLoginCmd(), NewLogoutCmd())
	return cmd
}

// Functions ---------------------------------------------------------------------------------------------------------

// ensureDefaultVaultIssuer adds a vault-flavored Issuer to state, derived
// from this project's own AppConfig, unless one is already present — the
// Vault-backed demo needs no separate setup step the way
// scripts/keycloak-setup's transform is for Keycloak, since everything it
// needs is already in config/oid4vc-config.yml.
func ensureDefaultVaultIssuer(state *wallet.WalletState) error {
	if _, ok := state.Issuers[vaultIssuerAlias]; ok {
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

	state.Issuers[vaultIssuerAlias] = issuer
	if state.DefaultIssuer == "" {
		state.DefaultIssuer = vaultIssuerAlias
	}
	return nil
}

// resolveIssuer loads the wallet state and returns it together with the
// named issuer — falling back to the wallet's DefaultIssuer when alias is
// empty — and the alias it was found under, so callers can mutate the
// issuer and save the WalletState back.
func resolveIssuer(alias string) (*wallet.WalletState, string, *wallet.Issuer, error) {
	state, err := wallet.LoadWalletState(walletDir)
	if err != nil {
		return nil, "", nil, err
	}
	if err := ensureDefaultVaultIssuer(state); err != nil {
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
