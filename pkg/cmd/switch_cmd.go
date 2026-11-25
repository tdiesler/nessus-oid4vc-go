package cmd

import (
	"github.com/spf13/cobra"
	co "github.com/tdiesler/nessus-oid4vc-go/pkg/common"
	"github.com/tdiesler/nessus-oid4vc-go/pkg/holder"
)

// SwitchOpts ================================================================================================================

// SwitchOpts holds switch's flag values: the issuer alias to make the
// holder's new default.
type SwitchOpts struct {
	Issuer string
}

// NewSwitchOpts constructs a SwitchOpts.
func NewSwitchOpts() *SwitchOpts {
	return &SwitchOpts{}
}

// Run makes o.Issuer the holder's new default issuer.
func (o *SwitchOpts) Run() error {
	if err := holder.SwitchIssuer(o.Issuer); err != nil {
		return err
	}
	state, err := holder.LoadWalletState()
	if err != nil {
		return err
	}
	issuer := state.Issuers[state.DefaultIssuer]
	co.InfoF("%s:%s", state.DefaultIssuer, issuer.DefaultUser)
	return nil
}

// NewSwitchCmd builds the switch command.
func NewSwitchCmd() *cobra.Command {
	opts := NewSwitchOpts()
	cmd := &cobra.Command{
		Use:   "switch <issuer>",
		Short: "Switch the holder's default issuer",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			opts.Issuer = args[0]
			return opts.Run()
		},
	}
	return cmd
}
