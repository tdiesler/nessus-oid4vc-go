package main

import (
	"strings"

	"github.com/chzyer/readline"
	"github.com/spf13/cobra"
	co "github.com/tdiesler/nessus-oid4vc-go/pkg/common"
)

// ReplOpts ================================================================================================================

// ReplOpts holds repl's flag values — currently none of its own, but kept
// for consistency with every other subcommand's Opts/Run shape.
type ReplOpts struct {
	RootOpts
}

// NewReplOpts constructs a ReplOpts.
func NewReplOpts() *ReplOpts {
	return &ReplOpts{}
}

// Run opens an interactive prompt that runs oid4vc's own subcommands one
// line at a time, in-process, until the user exits with "exit", "quit", or
// Ctrl-D.
func (o *ReplOpts) Run() error {
	rl, err := readline.New("oid4vc> ")
	if err != nil {
		return err
	}
	defer func() { _ = rl.Close() }()

	for {
		line, err := rl.Readline()
		if err != nil { // io.EOF (Ctrl-D) or readline.ErrInterrupt (Ctrl-C)
			return nil
		}

		if exit := runReplLine(line); exit {
			return nil
		}
	}
}

// NewReplCmd builds the repl command.
func NewReplCmd() *cobra.Command {
	opts := NewReplOpts()
	cmd := &cobra.Command{
		Use:   "repl",
		Short: "Run an interactive oid4vc prompt",
		RunE: func(cmd *cobra.Command, args []string) error {
			return opts.Run()
		},
	}
	bindRootOpts(cmd, &opts.RootOpts)
	return cmd
}

// Functions ---------------------------------------------------------------------------------------------------------

// runReplLine tokenizes line by whitespace and runs it against a fresh
// oid4vc command tree, printing any resulting error instead of exiting the
// process. Returns true if line requests the REPL to exit ("exit"/"quit"),
// false otherwise, including for a blank line.
func runReplLine(line string) bool {
	line = strings.TrimSpace(line)
	if line == "" {
		return false
	}
	if line == "exit" || line == "quit" {
		return true
	}

	cmd := NewRootCmd()
	cmd.SilenceUsage = true
	cmd.SilenceErrors = true
	cmd.SetArgs(strings.Fields(line))
	if err := cmd.Execute(); err != nil {
		co.ErrorE(err)
	}
	return false
}
