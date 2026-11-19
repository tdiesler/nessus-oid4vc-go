package wallet

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"path/filepath"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/stretchr/testify/require"
)

func TestConnectionRoundTripsThroughJSON(t *testing.T) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
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
	vaultState.DefaultIssuer = "vault-dev"
	vaultState.Issuers["vault-dev"] = NewIssuer(IssuerVault, "http://vault.test/v1/identity/oidc/provider/oid4vc")
	require.NoError(t, vaultState.SaveIssuer(dir, IssuerVault))

	kcState := NewWalletState()
	kcState.Issuers["keycloak"] = NewIssuer(IssuerKeycloak, "http://keycloak.test/realms/oid4vci")
	require.NoError(t, kcState.SaveIssuer(dir, IssuerKeycloak))

	merged, err := LoadWalletState(dir)
	require.NoError(t, err)
	require.Equal(t, "vault-dev", merged.DefaultIssuer)
	require.Len(t, merged.Issuers, 2)
	require.Equal(t, IssuerVault, merged.Issuers["vault-dev"].Flavor)
	require.Equal(t, IssuerKeycloak, merged.Issuers["keycloak"].Flavor)
}

func TestLoadNoFiles(t *testing.T) {
	dir := t.TempDir()

	state, err := LoadWalletState(dir)
	require.NoError(t, err)
	require.Empty(t, state.Issuers)
}

func TestSaveIssuerOnlyWritesMatchingKind(t *testing.T) {
	dir := t.TempDir()

	state := NewWalletState()
	state.Issuers["vault-dev"] = NewIssuer(IssuerVault, "http://vault.test")
	state.Issuers["keycloak"] = NewIssuer(IssuerKeycloak, "http://keycloak.test/realms/oid4vci")
	require.NoError(t, state.SaveIssuer(dir, IssuerVault))

	vaultOnly, err := LoadWalletState(dir)
	require.NoError(t, err)
	require.Len(t, vaultOnly.Issuers, 1)
	require.Contains(t, vaultOnly.Issuers, "vault-dev")

	require.NoFileExists(t, filepath.Join(dir, "wallet.keycloak.json"))
}
