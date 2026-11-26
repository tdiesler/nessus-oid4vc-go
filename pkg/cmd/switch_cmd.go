package cmd

import (
	"github.com/spf13/cobra"
	co "github.com/tdiesler/nessus-oid4vc-go/pkg/common"
	"github.com/tdiesler/nessus-oid4vc-go/pkg/holder"
)

// NewSwitchCmd builds the switch command, grouping holder state switches.
// With no subcommand it displays help.
func NewSwitchCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "switch",
		Short: "Switch the holder's active issuer",
	}
	cmd.AddCommand(NewSwitchIssuerCmd())
	return cmd
}

// SwitchIssuerOpts ===========================================================================================================

// SwitchIssuerOpts holds switch issuer's flag values — currently none: with
// exactly two issuers configured, it switches to whichever one isn't
// currently the default. Naming a specific issuer is deferred until a
// third issuer of the same type (e.g. a second Vault deployment) exists
// and "the other one" stops being unambiguous.
type SwitchIssuerOpts struct {
}

// NewSwitchIssuerOpts constructs a SwitchIssuerOpts.
func NewSwitchIssuerOpts() *SwitchIssuerOpts {
	return &SwitchIssuerOpts{}
}

// Run makes the holder's one other configured issuer the new default.
func (o *SwitchIssuerOpts) Run() error {
	alias, err := holder.OtherIssuer()
	if err != nil {
		return err
	}
	if err := holder.SwitchIssuer(alias); err != nil {
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

// NewSwitchIssuerCmd builds the switch issuer command.
func NewSwitchIssuerCmd() *cobra.Command {
	opts := NewSwitchIssuerOpts()
	cmd := &cobra.Command{
		Use:   "issuer",
		Short: "Switch the holder's default issuer to the other configured issuer",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return opts.Run()
		},
	}
	return cmd
}
