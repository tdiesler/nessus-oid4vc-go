package oid4vci

import (
	"fmt"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
	co "github.com/tdiesler/nessus-oid4vc-go/pkg/common"
	"github.com/tdiesler/nessus-oid4vc-go/pkg/holder"
)

// StartTestIssuerServer constructs and starts an AuthorizationServer for issuer,
// bound to addr.
func StartTestIssuerServer(addr string) (*AuthorizationServer, error) {
	as, err := NewAuthorizationServer(addr)
	if err != nil {
		return nil, err
	}
	if err := as.Start(); err != nil {
		return nil, err
	}
	return as, nil
}

// StopTestIssuerServer shuts down as, ignoring any error — paired with
// StartTestIssuerServer in a TestMain's teardown.
func StopTestIssuerServer(as *AuthorizationServer) {
	_ = as.Shutdown()
}

// SetupTestIssuerVault points the holder's vault issuer at addr — this
// package's own test AuthorizationServer, rather than whatever a prior
// manual `oid4vc` run against the real server last left on disk — and
// snapshots wallet.vault.json first, so the caller can restore it once
// tests are done.
func SetupTestIssuerVault(addr string) (*co.FileSnapshot, error) {

	path := filepath.Join(co.HomeDir(), ".config", "wallet.vault.json")
	snapshot, err := co.NewFileSnapshot(path)
	if err != nil {
		return nil, err
	}

	cfg, err := co.GetAppConfig()
	if err != nil {
		return nil, err
	}

	state, err := holder.LoadWalletState()
	if err != nil {
		return nil, err
	}

	issuer := holder.NewIssuer(holder.IssuerVault, addr)
	issuer.RedirectUri = cfg.RedirectUri
	issuer.DefaultClient = cfg.OidcClient
	issuer.DefaultUser = co.UserAlice
	issuer.Users[co.UserAlice] = holder.NewConnection(cfg.OidcClient)
	state.Issuers[holder.IssuerVault] = issuer

	if err := state.SaveWalletState(holder.IssuerVault); err != nil {
		return nil, err
	}
	return snapshot, nil
}

func TakeWalletSnapshot(t *testing.T, alias string) *co.FileSnapshot {
	walletDir := filepath.Join(co.HomeDir(), ".config")
	fileName := fmt.Sprintf("wallet.%s.json", alias)
	snapshot, err := co.NewFileSnapshot(filepath.Join(walletDir, fileName))
	require.NoError(t, err)
	return snapshot
}
