package main

import (
	"os"
	"path/filepath"
	"testing"

	co "github.com/tdiesler/nessus-oid4vc-go/pkg/common"
	"github.com/tdiesler/nessus-oid4vc-go/pkg/oid4vci"
	"github.com/tdiesler/nessus-oid4vc-go/pkg/wallet"
)

// testOid4vciAddr and testRedirectUri are config/oid4vc-config.yml's real
// Oid4vci.Addr/Vault.RedirectURI values with their ports offset by 10 —
// distinct from pkg/oid4vci's and pkg/oauth's own tests, which bind those
// exact real ports, so all three can run as the separate, concurrent
// processes `go test ./...` makes of them without colliding.
const (
	testOid4vciAddr = "127.0.0.1:9010"
	testRedirectUri = "http://localhost:8410/callback"
)

// TestMain runs this package's tests the same way a developer would use
// the CLI from a terminal at the repo root: against the real .config
// directory, with this project's real AppConfig overridden only to shift
// Oid4vci.Addr/Vault.RedirectURI onto testOid4vciAddr/testRedirectUri for
// this process — so an "alice" session a test logs into is the same shape
// of wallet state a manual `oid4vc login` run would produce. The one thing
// a terminal session wouldn't otherwise have running is the oid4vci server
// itself, so TestMain starts that.
func TestMain(m *testing.M) {
	co.SetupHomeDir()
	walletDir = filepath.Join(co.SetupHomeDir(), ".config")

	_ = os.Setenv("NESSUS_OID4VC_OID4VCI_ADDR", testOid4vciAddr)
	_ = os.Setenv("NESSUS_OID4VC_VAULT_REDIRECTURI", testRedirectUri)

	cfg, err := co.GetAppConfig()
	if err != nil {
		co.ErrorE(err)
		os.Exit(1)
	}

	as, err := oid4vci.NewAuthorizationServer("http://"+cfg.Oid4vciAddr, cfg.Oid4vciAddr)
	if err != nil {
		co.ErrorE(err)
		os.Exit(1)
	}
	if err := as.Start(); err != nil {
		co.ErrorE(err)
		os.Exit(1)
	}

	// Overwrite the vault issuer unconditionally rather than relying on
	// ensureDefaultVaultIssuer's "only when missing" default: a leftover
	// entry from an earlier run (manual or test) would otherwise keep
	// pointing at whatever address that run used, not this one.
	state, err := wallet.LoadWalletState(walletDir)
	if err != nil {
		co.ErrorE(err)
		os.Exit(1)
	}
	vaultIssuer := wallet.NewIssuer(wallet.IssuerVault, as.Issuer)
	vaultIssuer.RedirectUri = cfg.RedirectUri
	vaultIssuer.DefaultClient = cfg.OidcClient
	vaultIssuer.DefaultUser = co.UserAlice
	vaultIssuer.Users[co.UserAlice] = wallet.NewConnection(cfg.OidcClient)
	state.Issuers[vaultIssuerAlias] = vaultIssuer
	if err := state.SaveIssuer(walletDir, wallet.IssuerVault); err != nil {
		co.ErrorE(err)
		os.Exit(1)
	}

	code := m.Run()

	_ = as.Shutdown()
	os.Exit(code)
}
