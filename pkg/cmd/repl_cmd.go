package cmd

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
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
// before the first prompt. Command history persists across restarts in
// .config/history.txt, excluding "exit"/"quit"/"history" lines and
// consecutive duplicates of the previous line. "history" lists it as a
// 1-based numbered list, and "!N" re-runs its Nth entry, both the way sh's
// builtins do.
func (o *ReplOpts) Run() error {
	fmt.Println(rootShort)
	if alias, username, err := holder.CurrentState(o.Issuer); err == nil {
		co.InfoF("%s:%s", alias, username)
	} else {
		fmt.Println(err)
	}

	historyFile := filepath.Join(co.HomeDir(), ".config", "history.txt")
	history := loadReplHistory(historyFile)

	rl, err := readline.NewEx(&readline.Config{
		Prompt:                 "oid4vc> ",
		AutoComplete:           replCompleter(),
		HistoryFile:            historyFile,
		DisableAutoSaveHistory: true,
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

		line, ok := expandReplHistoryRef(line, history)
		if !ok {
			continue
		}
		trimmed := strings.TrimSpace(line)

		if trimmed != "" && trimmed != "exit" && trimmed != "quit" && trimmed != "history" && (len(history) == 0 || trimmed != history[len(history)-1]) {
			_ = rl.SaveHistory(trimmed)
			history = append(history, trimmed)
		}

		if trimmed == "history" {
			printReplHistory(history)
			continue
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

// expandReplHistoryRef resolves a "!N" line (1-based, as shown by "history")
// into history's Nth entry, echoing it the way sh echoes an expanded "!N"
// before running it. Returns line unchanged, ok=true if it isn't a "!N"
// reference, and ok=false after printing an error if N is out of range.
func expandReplHistoryRef(line string, history []string) (resolved string, ok bool) {
	trimmed := strings.TrimSpace(line)
	if !strings.HasPrefix(trimmed, "!") {
		return line, true
	}

	n, err := strconv.Atoi(trimmed[1:])
	if err != nil || n < 1 || n > len(history) {
		fmt.Printf("%s: event not found\n", trimmed)
		return "", false
	}

	resolved = history[n-1]
	fmt.Println(resolved)
	return resolved, true
}

// loadReplHistory reads path's previously persisted history lines (see
// Run's readline.Config.HistoryFile), returning nil if path doesn't exist
// yet.
func loadReplHistory(path string) []string {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}

	var history []string
	for _, line := range strings.Split(string(data), "\n") {
		if trimmed := strings.TrimSpace(line); trimmed != "" {
			history = append(history, trimmed)
		}
	}
	return history
}

// printReplHistory prints history as a 1-based numbered list, the way sh's
// "history" builtin does.
func printReplHistory(history []string) {
	for i, cmd := range history {
		fmt.Printf("%5d  %s\n", i+1, cmd)
	}
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
