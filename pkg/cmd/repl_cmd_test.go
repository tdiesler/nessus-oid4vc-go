package cmd

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
	co "github.com/tdiesler/nessus-oid4vc-go/pkg/common"
	"github.com/tdiesler/nessus-oid4vc-go/pkg/holder"
)

// TestCobraCompletions confirms the REPL's tab-completer (driven by
// cobraCompletions, see repl_cmd.go) mirrors newReplCommandTree's command
// names and flag names: top-level commands are present, repl and
// run-server are excluded, a subcommand group's (show's) own children are
// offered too, and a command's own flags are offered once typing "--".
func TestCobraCompletions(t *testing.T) {
	topLevel := cobraCompletions([]string{""})
	require.Contains(t, topLevel, "key")
	require.Contains(t, topLevel, "show")
	require.NotContains(t, topLevel, "repl")
	require.NotContains(t, topLevel, "run-server")

	show := cobraCompletions([]string{"show", ""})
	require.Contains(t, show, "credential-issuer-metadata")
	require.Contains(t, show, "openid-configuration")
	require.Contains(t, show, "state")

	loginFlags := cobraCompletions([]string{"login", "--"})
	require.Contains(t, loginFlags, "--issuer")
	require.Contains(t, loginFlags, "--client")
	require.Contains(t, loginFlags, "--user")
	require.Contains(t, loginFlags, "--scope")
}

// TestCompleteFlagValues confirms completion.go's flag-value completers
// resolve a command line's already-typed --issuer/--user against a
// synthetic issuer (torn down via t.Cleanup, leaving real holder state
// untouched), offering its known usernames, previously-used client IDs,
// holder key names, and credential identifiers.
func TestCompleteFlagValues(t *testing.T) {
	const alias = "repltest"
	path := filepath.Join(co.HomeDir(), ".config", "wallet."+alias+".json")
	snapshot, err := co.NewFileSnapshot(path)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, snapshot.Restore()) })

	issuer := holder.NewIssuer(alias, "https://example.invalid")
	issuer.DefaultClient = "default-client"
	conn := holder.NewConnection(issuer.DefaultClient)
	kid, err := conn.AddHolderKey("es256#1")
	require.NoError(t, err)
	conn.AuthorizationDetails = []holder.AuthorizationDetail{
		holder.NewAuthorizationDetail("openid_credential", "natural_person", []string{"cred-1", "cred-2"}),
	}
	issuer.Users["alice"] = conn

	state, err := holder.LoadWalletState()
	require.NoError(t, err)
	state.Issuers[alias] = issuer
	require.NoError(t, state.SaveWalletState(alias))

	aliasCmd := NewLoginCmd()
	aliases, _ := completeIssuerAlias(aliasCmd, nil, "")
	require.Contains(t, aliases, alias)

	loginCmd := NewLoginCmd()
	require.NoError(t, loginCmd.ParseFlags([]string{"--issuer", alias}))
	users, _ := completeUsername(loginCmd, nil, "")
	require.Equal(t, []string{"alice"}, users)
	clients, _ := completeClientId(loginCmd, nil, "")
	require.Equal(t, []string{"default-client"}, clients)

	vcCmd := NewVcGetCmd()
	require.NoError(t, vcCmd.ParseFlags([]string{"--issuer", alias, "--user", "alice"}))
	keys, _ := completeHolderKey(vcCmd, nil, "")
	require.Equal(t, []string{kid}, keys)
	ids, _ := completeCredentialIdentifier(vcCmd, nil, "")
	require.ElementsMatch(t, []string{"cred-1", "cred-2"}, ids)
}

// TestRunReplLine confirms the REPL's own exit/blank-line handling, without
// invoking a real subcommand: "exit" and "quit" request the REPL to stop, a
// blank (or whitespace-only) line is a no-op, and anything else keeps the
// REPL running.
func TestRunReplLine(t *testing.T) {
	require.True(t, runReplLine("exit"))
	require.True(t, runReplLine("quit"))
	require.True(t, runReplLine("  exit  "))

	require.False(t, runReplLine(""))
	require.False(t, runReplLine("   "))

	require.False(t, runReplLine("key"))
}
