package main

import (
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/tdiesler/nessus-oid4vc-go/pkg/holder"
)

// TestKeyCreate drives key create against the vault issuer. Key creation
// is a local, flavor-agnostic holder operation — it never branches on
// issuer.Flavor, unlike login/logout — so there's nothing issuer-specific
// to exercise twice here; see pkg/holder's own TestConnectionAddHolderKey
// for the underlying naming/replace logic. This confirms a created key is
// added to the issuer's default user (whose Connection may not exist
// yet), auto-derives its own name, and an explicitly named key becomes
// the new default, persisting to the holder's on-disk state.
func TestKeyCreate(t *testing.T) {
	iss := holder.IssuerVault

	snapshot := takeWalletSnapshot(t, iss)
	defer func() { _ = snapshot.Restore() }()

	w, err := holder.NewWallet(iss, "")
	require.NoError(t, err)
	username := w.Username()
	require.NotEmpty(t, username)

	before := 0
	if conn, ok := w.Issuer().Users[username]; ok {
		before = len(conn.Keys)
	}

	create := NewKeyCreateOpts()
	create.Issuer = iss
	require.NoError(t, create.Run())

	w, err = holder.NewWallet(iss, "")
	require.NoError(t, err)
	conn := w.Issuer().Users[username]
	require.NotNil(t, conn)
	require.Len(t, conn.Keys, before+1)
	require.NotEmpty(t, conn.DefaultKey)
	require.Equal(t, conn.DefaultKey, conn.Keys[len(conn.Keys)-1].KeyID)

	// A unique name each run: a repeated literal would replace rather
	// than add on a second run against this same real holder state,
	// breaking the Len assertion below.
	keyName := fmt.Sprintf("test-key-cmd-%d", time.Now().UnixNano())
	named := NewKeyCreateOpts()
	named.Issuer = iss
	named.Name = keyName
	require.NoError(t, named.Run())

	w, err = holder.NewWallet(iss, "")
	require.NoError(t, err)
	conn = w.Issuer().Users[username]
	require.Equal(t, keyName, conn.DefaultKey)
	require.Len(t, conn.Keys, before+2)
}
