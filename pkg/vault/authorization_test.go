package vault

import (
	"testing"

	"github.com/stretchr/testify/require"
	co "github.com/tdiesler/nessus-oid4vc-go/pkg/common"
)

// TestNativeAuthorization logs in as Alice via Vault's
// native userpass auth method.
func TestNativeAuthorization(t *testing.T) {

	tokAlice, err := UserpassLogin(co.UserAlice, co.UserPassword)
	require.NoError(t, err)
	require.NotEmpty(t, tokAlice.Token)
}

// TestEntityDataAccess reads Alice's own Identity entity properties
// (identity/entity/name/alice), authenticated as her own login token per
// Vault's built-in self-read grant — Vault's Identity-system data, as
// opposed to TestKeyValueDataAccess's KV-sourced claims.
func TestEntityDataAccess(t *testing.T) {

	tokAlice, err := UserpassLogin(co.UserAlice, co.UserPassword)
	require.NoError(t, err)

	// Read Alice's entity properties, authenticated as her own token.
	entity, err := NewEntityAccessor().Entity(tokAlice, co.UserAlice)
	require.NoError(t, err)
	require.Equal(t, co.UserAlice, entity.Name)
	require.Equal(t, "Alice", entity.Metadata["firstName"])
	require.Equal(t, "Wonderland", entity.Metadata["familyName"])
	require.Equal(t, "alice@email.com", entity.Metadata["email"])
}

// TestKeyValueDataAccess reads Alice's own claims from Vault KV v2
// (secret/data/subjects/alice), authenticated as her own login token per
// the subject-self policy — the generic KV path ReadSubjectsKeyValueClaims
// wraps, as opposed to TestEntityDataAccess's Identity-system data.
func TestKeyValueDataAccess(t *testing.T) {

	tokAlice, err := UserpassLogin(co.UserAlice, co.UserPassword)
	require.NoError(t, err)

	// Read Alice's KV claims, authenticated as her own token.
	claims, err := NewKeyValueAccessor().ReadSubjectsKeyValueClaims(tokAlice, co.UserAlice)
	require.NoError(t, err)
	require.Equal(t, "Alice", claims["firstName"])
	require.Equal(t, "Wonderland", claims["familyName"])
	require.Equal(t, "alice@email.com", claims["email"])
}

// TestCrossEntityDataAccess demonstrates cross-entity data delivery: Max (the
// issuer) writes an offer to Alice's dedicated offer path, and Alice reads
// it back with her own login token — no delegated minting involved on the
// read side.
//
// This relies on two policies: Alice's templated subject-self policy,
// extended to read her own secret/data/offers/<name>
// path, and max's literal subject-offer-write-alice policy, granting write
// (not read) on that same path for Alice specifically. A writer can never
// get a templated grant onto someone else's path — {{identity.entity.name}}
// only ever resolves to the caller's own identity — so every cross-entity
// write grant is necessarily a literal, per-subject policy rather than a
// templated one.
func TestCrossEntityDataAccess(t *testing.T) {

	// Max writes an offer to Alice's offer path.
	maxToken, err := UserpassLogin(co.UserMax, co.UserPassword)
	require.NoError(t, err)

	kvAccessor := NewKeyValueAccessor()
	offer := map[string]any{"message": "You have a pending credential offer", "issuedBy": co.UserMax}
	err = kvAccessor.WriteKeyValueClaims(maxToken, SecretsPathOffers, co.UserAlice, offer)
	require.NoError(t, err)

	// Max cannot read the offer back himself.
	_, err = kvAccessor.ReadKeyValueClaims(maxToken, SecretsPathOffers, co.UserAlice)
	require.Error(t, err)

	// Alice reads the offer using her own existing login token.
	aliceToken, err := UserpassLogin(co.UserAlice, co.UserPassword)
	require.NoError(t, err)

	read, err := kvAccessor.ReadKeyValueClaims(aliceToken, SecretsPathOffers, co.UserAlice)
	require.NoError(t, err)
	require.Equal(t, offer["message"], read["message"])
	require.Equal(t, offer["issuedBy"], read["issuedBy"])

	// Alice cannot write to her own offer path.
	err = kvAccessor.WriteKeyValueClaims(aliceToken, SecretsPathOffers, co.UserAlice, offer)
	require.Error(t, err)
}
