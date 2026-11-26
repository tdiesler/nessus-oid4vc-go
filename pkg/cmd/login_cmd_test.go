package cmd

import (
	"testing"

	"github.com/stretchr/testify/require"
	co "github.com/tdiesler/nessus-oid4vc-go/pkg/common"
	"github.com/tdiesler/nessus-oid4vc-go/pkg/holder"
)

// TestLogin drives login then logout headlessly against each flavor — a
// real CredentialIssuer (fronting the real Vault) for "vault", and the
// real Keycloak realm scripts/keycloak-setup already configured for
// "keycloak" — confirming both the session a login establishes and its
// removal on logout persist to the holder's on-disk state.
func TestLogin(t *testing.T) {
	cases := []struct {
		flavor   string
		username string
		password string
	}{
		{flavor: holder.IssuerVault, username: co.UserAlice, password: co.UserPassword},
		{flavor: holder.IssuerKeycloak, username: co.UserAlice, password: co.UserPassword},
	}

	for _, c := range cases {
		t.Run(c.flavor, func(t *testing.T) {

			login := NewLoginOpts()
			login.Issuer = c.flavor
			login.User = c.username
			login.Password = c.password
			require.NoError(t, login.Run())

			w, err := holder.NewWallet(c.flavor, c.username)
			require.NoError(t, err)
			require.Equal(t, c.flavor, w.Issuer().Alias)
			conn := w.Issuer().Users[c.username]
			require.NotNil(t, conn)
			require.NotNil(t, conn.Token)
			require.NotEmpty(t, conn.Token.AccessToken)
			require.False(t, conn.Token.Expired())

			logout := NewLogoutOpts()
			logout.Issuer = c.flavor
			logout.User = c.username
			require.NoError(t, logout.Run())

			w, err = holder.NewWallet(c.flavor, c.username)
			require.NoError(t, err)
			conn = w.Issuer().Users[c.username]
			require.NotNil(t, conn)
			require.Nil(t, conn.Token)
		})
	}
}
