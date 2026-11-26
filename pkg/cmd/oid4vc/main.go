package main

import (
	"os"

	"github.com/tdiesler/nessus-oid4vc-go/pkg/cmd"
	co "github.com/tdiesler/nessus-oid4vc-go/pkg/common"
	"github.com/tdiesler/nessus-oid4vc-go/pkg/holder"
	"github.com/tdiesler/nessus-oid4vc-go/pkg/oid4vci"
)

func main() {

	co.InitLogging()

	issuer, err := ensureDefaultVaultIssuer()
	if err != nil {
		co.ErrorE(err)
		os.Exit(1)
	}

	ci, err := oid4vci.NewCredentialIssuer(issuer.IssuerURL)
	if err != nil {
		co.ErrorE(err)
		os.Exit(1)
	}
	if err = ci.Start(); err != nil {
		co.ErrorE(err)
		os.Exit(1)
	}
	defer func() {
		_ = ci.Shutdown()
	}()

	if err = cmd.NewRootCmd().Execute(); err != nil {
		co.ErrorE(err)
		os.Exit(1)
	}
}

// ensureDefaultVaultIssuer adds a vault-flavored Issuer to state, derived
// from this project's own AppConfig, unless one is already present.
func ensureDefaultVaultIssuer() (*holder.Issuer, error) {

	state, err := holder.LoadWalletState()
	if err != nil {
		return nil, err
	}

	if iss, ok := state.Issuers[holder.IssuerVault]; ok {
		return iss, nil
	}

	cfg, err := co.GetAppConfig()
	if err != nil {
		return nil, err
	}

	issuer := holder.NewIssuer(holder.IssuerVault, cfg.Oid4vciAddr)
	issuer.RedirectUri = cfg.RedirectUri
	issuer.DefaultClient = cfg.OidcClient
	issuer.DefaultUser = co.UserAlice
	issuer.Users[co.UserAlice] = holder.NewConnection(cfg.OidcClient)

	state.Issuers[holder.IssuerVault] = issuer
	if state.DefaultIssuer == "" {
		state.DefaultIssuer = holder.IssuerVault
	}

	if err = state.SaveWalletState(issuer.Alias); err != nil {
		return nil, err
	}

	return issuer, nil
}
