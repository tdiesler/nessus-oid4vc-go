package wallet

import (
	"encoding/json"
	"path/filepath"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jose-util/generator"
	"github.com/stretchr/testify/require"
)

func TestConnectionAddHolderKey(t *testing.T) {
	conn := NewConnection("test-client")

	kid, err := conn.AddHolderKey("")
	require.NoError(t, err)
	require.Equal(t, "es256#1", kid)
	require.Equal(t, "es256#1", conn.DefaultKey)
	require.Len(t, conn.Keys, 1)

	kid, err = conn.AddHolderKey("")
	require.NoError(t, err)
	require.Equal(t, "es256#2", kid)
	require.Len(t, conn.Keys, 2)

	kid, err = conn.AddHolderKey("custom")
	require.NoError(t, err)
	require.Equal(t, "custom", kid)
	require.Equal(t, "custom", conn.DefaultKey)
	require.Len(t, conn.Keys, 3)

	// Re-creating a named key replaces the existing one with that name.
	kid, err = conn.AddHolderKey("custom")
	require.NoError(t, err)
	require.Equal(t, "custom", kid)
	require.Len(t, conn.Keys, 3)
}

func TestConnectionRoundTripsThroughJSON(t *testing.T) {
	_, privateKey, err := generator.NewSigningKey(jose.ES256, 0)
	require.NoError(t, err)

	conn := NewConnection("test-client").
		WithToken(NewToken("access-token", "refresh-token", time.Now().Truncate(time.Second)))
	conn.AuthorizationDetails = []AuthorizationDetail{
		NewAuthorizationDetail("openid_credential", "oid4vc_natural_person_sd", []string{"oid4vc_natural_person_sd_0000"}),
	}
	conn.Keys = []jose.JSONWebKey{{Key: privateKey, KeyID: "es256#1", Algorithm: "ES256", Use: "sig"}}

	data, err := json.Marshal(conn)
	require.NoError(t, err)

	var decoded Connection
	require.NoError(t, json.Unmarshal(data, &decoded))
	require.Equal(t, conn.Token.AccessToken, decoded.Token.AccessToken)
	require.True(t, conn.Token.ExpiresAt.Equal(decoded.Token.ExpiresAt))
	require.Equal(t, conn.AuthorizationDetails, decoded.AuthorizationDetails)
	require.Len(t, decoded.Keys, 1)
	require.Equal(t, "es256#1", decoded.Keys[0].KeyID)
}

func TestTokenExpired(t *testing.T) {
	token := NewToken("access-token", "refresh-token", time.Now().Add(-time.Minute))
	require.True(t, token.Expired())

	token = NewToken("access-token", "refresh-token", time.Now().Add(time.Minute))
	require.False(t, token.Expired())
}

func TestLoadMergesPerKindFiles(t *testing.T) {
	dir := t.TempDir()

	vaultState := NewWalletState()
	vaultState.DefaultIssuer = IssuerVault
	vaultState.Issuers[IssuerVault] = NewIssuer(IssuerVault, "http://vault.test/v1/identity/oidc/provider/oid4vc")
	require.NoError(t, vaultState.SaveWalletStateToDir(IssuerVault, dir))

	kcState := NewWalletState()
	kcState.Issuers[IssuerKeycloak] = NewIssuer(IssuerKeycloak, "http://keycloak.test/realms/oid4vci")
	require.NoError(t, kcState.SaveWalletStateToDir(IssuerKeycloak, dir))

	merged, err := LoadWalletStateFromDir(dir)
	require.NoError(t, err)
	require.Equal(t, IssuerVault, merged.DefaultIssuer)
	require.Len(t, merged.Issuers, 2)
	require.Equal(t, IssuerVault, merged.Issuers[IssuerVault].Flavor)
	require.Equal(t, IssuerKeycloak, merged.Issuers[IssuerKeycloak].Flavor)
}

func TestLoadNoFiles(t *testing.T) {
	dir := t.TempDir()

	state, err := LoadWalletStateFromDir(dir)
	require.NoError(t, err)
	require.Empty(t, state.Issuers)
}

func TestSaveIssuerOnlyWritesMatchingKind(t *testing.T) {
	dir := t.TempDir()

	state := NewWalletState()
	state.Issuers[IssuerVault] = NewIssuer(IssuerVault, "http://vault.test")
	state.Issuers[IssuerKeycloak] = NewIssuer(IssuerKeycloak, "http://keycloak.test/realms/oid4vci")
	require.NoError(t, state.SaveWalletStateToDir(IssuerVault, dir))

	vaultOnly, err := LoadWalletStateFromDir(dir)
	require.NoError(t, err)
	require.Len(t, vaultOnly.Issuers, 1)
	require.Contains(t, vaultOnly.Issuers, IssuerVault)

	require.NoFileExists(t, filepath.Join(dir, "wallet.keycloak.json"))
}
