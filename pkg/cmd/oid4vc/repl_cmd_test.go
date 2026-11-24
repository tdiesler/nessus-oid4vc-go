package main

import (
	"testing"

	"github.com/stretchr/testify/require"
)

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
