package cmd

import (
	"strings"
	"testing"

	"github.com/chzyer/readline"
	"github.com/stretchr/testify/require"
)

// TestReplCompleter confirms the REPL's tab-completer mirrors
// newReplCommandTree's command names: top-level commands are present, repl
// and run-server are excluded, and a subcommand group's (show's) own
// children are offered too.
func TestReplCompleter(t *testing.T) {
	root := replCompleter()

	names := func(items []readline.PrefixCompleterInterface) []string {
		out := make([]string, len(items))
		for i, item := range items {
			out[i] = strings.TrimSpace(string(item.GetName()))
		}
		return out
	}

	topLevel := names(root.GetChildren())
	require.Contains(t, topLevel, "key")
	require.Contains(t, topLevel, "show")
	require.NotContains(t, topLevel, "repl")
	require.NotContains(t, topLevel, "run-server")

	var show readline.PrefixCompleterInterface
	for _, item := range root.GetChildren() {
		if strings.TrimSpace(string(item.GetName())) == "show" {
			show = item
		}
	}
	require.NotNil(t, show)
	require.Contains(t, names(show.GetChildren()), "credential-issuer-metadata")
	require.Contains(t, names(show.GetChildren()), "openid-configuration")
	require.Contains(t, names(show.GetChildren()), "state")
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
