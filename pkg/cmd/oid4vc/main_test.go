package main

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
	co "github.com/tdiesler/nessus-oid4vc-go/pkg/common"
	"github.com/tdiesler/nessus-oid4vc-go/pkg/oid4vci"
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
// of holder state a manual `oid4vc login` run would produce. The one thing
// a terminal session wouldn't otherwise have running is the oid4vci server
// itself, so TestMain starts that.
func TestMain(m *testing.M) {
	co.HomeDir()

	_ = os.Setenv("NESSUS_OID4VC_OID4VCI_ADDR", testOid4vciAddr)
	_ = os.Setenv("NESSUS_OID4VC_VAULT_REDIRECTURI", testRedirectUri)

	as, err := oid4vci.NewAuthorizationServerFromConfig()
	if err != nil {
		co.ErrorE(err)
		os.Exit(1)
	}
	if err = as.Start(); err != nil {
		co.ErrorE(err)
		os.Exit(1)
	}

	defer func() { _ = as.Shutdown() }()

	os.Exit(m.Run())
}

func takeWalletSnapshot(t *testing.T, flavor string) *co.FileSnapshot {
	walletDir := filepath.Join(co.HomeDir(), ".config")
	fileName := fmt.Sprintf("holder.%s.json", flavor)
	snapshot, err := co.NewFileSnapshot(filepath.Join(walletDir, fileName))
	require.NoError(t, err)
	return snapshot
}
