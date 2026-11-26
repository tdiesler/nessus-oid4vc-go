package cmd

import (
	"os"
	"os/signal"
	"syscall"

	"github.com/spf13/cobra"
	co "github.com/tdiesler/nessus-oid4vc-go/pkg/common"
	"github.com/tdiesler/nessus-oid4vc-go/pkg/oid4vci"
)

// RunServerOpts ============================================================================================================

// RunServerOpts holds run-server's flag values — currently none, since
// unlike every other subcommand it doesn't embed RootOpts: it starts this
// process' own oid4vci CredentialIssuer rather than operating against
// one as a client.
type RunServerOpts struct{}

// NewRunServerOpts constructs a RunServerOpts.
func NewRunServerOpts() *RunServerOpts {
	return &RunServerOpts{}
}

// Run starts the oid4vci CredentialIssuer built from this project's own
// AppConfig, blocking until SIGINT/SIGTERM.
func (o *RunServerOpts) Run() error {

	ci, err := oid4vci.NewCredentialIssuerFromConfig()
	if err != nil {
		return err
	}
	if err = ci.Start(); err != nil {
		return err
	}
	co.InfoF("OID4VCI Server listening on %s", ci.BaseURL)

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	<-sigCh

	co.InfoF("OID4VCI Server shutting down")
	return ci.Shutdown()
}

// NewRunServerCmd builds the run-server command.
func NewRunServerCmd() *cobra.Command {
	opts := NewRunServerOpts()
	cmd := &cobra.Command{
		Use:   "run-server",
		Short: "Run the OID4VCI Server",
		RunE: func(cmd *cobra.Command, args []string) error {
			return opts.Run()
		},
	}
	return cmd
}
