package oid4vci

import (
	"fmt"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
	co "github.com/tdiesler/nessus-oid4vc-go/pkg/common"
	"github.com/tdiesler/nessus-oid4vc-go/pkg/holder"
)

// StartTestIssuer constructs and starts a CredentialIssuer for issuer,
// bound to addr.
func StartTestIssuer(addr string) (*CredentialIssuer, error) {
	ci, err := NewCredentialIssuer(addr)
	if err != nil {
		return nil, err
	}
	if err := ci.Start(); err != nil {
		return nil, err
	}
	return ci, nil
}

// StopTestIssuer shuts down ci, ignoring any error — paired with
// StartTestIssuer in a TestMain's teardown.
func StopTestIssuer(ci *CredentialIssuer) {
	_ = ci.Shutdown()
}

// SetupTestIssuer points the holder's vault issuer at addr — this
// package's own test CredentialIssuer, rather than whatever a prior
// manual `oid4vc` run against the real server last left on disk — and
// snapshots wallet.vault.json first, so the caller can restore it.
func SetupTestIssuer(addr string) (*co.FileSnapshot, error) {

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
