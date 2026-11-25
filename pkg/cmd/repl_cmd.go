package cmd

import (
	"fmt"
	"strings"

	"github.com/chzyer/readline"
	"github.com/spf13/cobra"
	co "github.com/tdiesler/nessus-oid4vc-go/pkg/common"
	"github.com/tdiesler/nessus-oid4vc-go/pkg/holder"
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
// Ctrl-D. Prints oid4vc's title and o.Issuer's current issuer:user state
// before the first prompt.
func (o *ReplOpts) Run() error {
	fmt.Println(rootShort)
	if alias, username, err := holder.CurrentState(o.Issuer); err == nil {
		co.InfoF("%s:%s", alias, username)
	} else {
		fmt.Println(err)
	}

	rl, err := readline.NewEx(&readline.Config{
		Prompt:       "oid4vc> ",
		AutoComplete: replCompleter(),
	})
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

// newReplCommandTree builds a fresh oid4vc command tree with repl and
// run-server removed — neither sensible from within an already-running
// REPL.
func newReplCommandTree() *cobra.Command {
	cmd := NewRootCmd()
	for _, name := range []string{"repl", "run-server"} {
		if sub, _, err := cmd.Find([]string{name}); err == nil {
			cmd.RemoveCommand(sub)
		}
	}
	return cmd
}

// replCompleter builds a readline tab-completer mirroring newReplCommandTree's
// command names, recursively through every level of subcommand — so typing
// e.g. "show c" and pressing Tab offers every show subcommand starting
// with "c".
func replCompleter() *readline.PrefixCompleter {
	return readline.NewPrefixCompleter(completerItems(newReplCommandTree())...)
}

// runReplLine tokenizes line by whitespace and runs it against a fresh
// command tree (see newReplCommandTree), printing any resulting error
// instead of exiting the process. Returns true if line requests the REPL
// to exit ("exit"/"quit"), false otherwise, including for a blank line.
func runReplLine(line string) bool {
	line = strings.TrimSpace(line)
	if line == "" {
		return false
	}
	if line == "exit" || line == "quit" {
		return true
	}

	cmd := newReplCommandTree()
	cmd.SilenceUsage = true
	cmd.SilenceErrors = true
	cmd.SetArgs(strings.Fields(line))
	if err := cmd.Execute(); err != nil {
		co.ErrorE(err)
	}
	return false
}

// completerItems builds one readline.PrefixCompleterInterface per direct
// subcommand of cmd, each recursively carrying its own subcommands.
func completerItems(cmd *cobra.Command) []readline.PrefixCompleterInterface {
	children := cmd.Commands()
	items := make([]readline.PrefixCompleterInterface, 0, len(children))
	for _, child := range children {
		items = append(items, readline.PcItem(child.Name(), completerItems(child)...))
	}
	return items
}
