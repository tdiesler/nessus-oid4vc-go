package main

import (
	"testing"

	"github.com/stretchr/testify/require"
	co "github.com/tdiesler/nessus-oid4vc-go/pkg/common"
	"github.com/tdiesler/nessus-oid4vc-go/pkg/wallet"
)

// TestLogin drives login then logout headlessly against each flavor — a
// real AuthorizationServer (fronting the real Vault) for "vault", and the
// real Keycloak realm scripts/keycloak-setup already configured for
// "keycloak" — confirming both the session a login establishes and its
// removal on logout persist to the wallet's on-disk state.
func TestLogin(t *testing.T) {
	cases := []struct {
		flavor   string
		username string
		password string
	}{
		{flavor: wallet.IssuerVault, username: co.UserAlice, password: co.UserPassword},
		{flavor: wallet.IssuerKeycloak, username: co.UserAlice, password: co.UserPassword},
	}

	for _, c := range cases {
		t.Run(c.flavor, func(t *testing.T) {

			login := NewLoginOpts()
			login.Issuer = c.flavor
			login.User = c.username
			login.Password = c.password
			require.NoError(t, login.Run())

			_, alias, issuer, err := resolveIssuer(c.flavor)
			require.NoError(t, err)
			require.Equal(t, c.flavor, alias)
			conn := issuer.Users[c.username]
			require.NotNil(t, conn)
			require.NotNil(t, conn.Token)
			require.NotEmpty(t, conn.Token.AccessToken)
			require.False(t, conn.Token.Expired())

			logout := NewLogoutOpts()
			logout.Issuer = c.flavor
			logout.User = c.username
			require.NoError(t, logout.Run())

			_, _, issuer, err = resolveIssuer(c.flavor)
			require.NoError(t, err)
			conn = issuer.Users[c.username]
			require.NotNil(t, conn)
			require.Nil(t, conn.Token)
		})
	}
}
