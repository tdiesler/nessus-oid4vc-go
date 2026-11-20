package main

import (
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/tdiesler/nessus-oid4vc-go/pkg/wallet"
)

// TestKeyCreate drives key create against the vault issuer. Key creation
// is a local, flavor-agnostic wallet operation — it never branches on
// issuer.Flavor, unlike login/logout — so there's nothing issuer-specific
// to exercise twice here; see pkg/wallet's own TestConnectionAddHolderKey
// for the underlying naming/replace logic. This confirms a created key is
// added to the issuer's default user (whose Connection may not exist
// yet), auto-derives its own name, and an explicitly named key becomes
// the new default, persisting to the wallet's on-disk state.
func TestKeyCreate(t *testing.T) {
	const flavor = string(wallet.IssuerVault)

	snapshot := takeWalletSnapshot(t, flavor)
	defer func() { _ = snapshot.Restore() }()

	_, _, issuer, err := resolveIssuer(flavor)
	require.NoError(t, err)
	username := issuer.DefaultUser
	require.NotEmpty(t, username)

	before := 0
	if conn, ok := issuer.Users[username]; ok {
		before = len(conn.Keys)
	}

	create := NewKeyCreateOpts()
	create.Issuer = flavor
	require.NoError(t, create.Run())

	_, _, issuer, err = resolveIssuer(flavor)
	require.NoError(t, err)
	conn := issuer.Users[username]
	require.NotNil(t, conn)
	require.Len(t, conn.Keys, before+1)
	require.NotEmpty(t, conn.DefaultKey)
	require.Equal(t, conn.DefaultKey, conn.Keys[len(conn.Keys)-1].KeyID)

	// A unique name each run: a repeated literal would replace rather
	// than add on a second run against this same real wallet state,
	// breaking the Len assertion below.
	keyName := fmt.Sprintf("test-key-cmd-%d", time.Now().UnixNano())
	named := NewKeyCreateOpts()
	named.Issuer = flavor
	named.Name = keyName
	require.NoError(t, named.Run())

	_, _, issuer, err = resolveIssuer(flavor)
	require.NoError(t, err)
	conn = issuer.Users[username]
	require.Equal(t, keyName, conn.DefaultKey)
	require.Len(t, conn.Keys, before+2)
}
