package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
	"github.com/tdiesler/nessus-oid4vc-go/pkg/holder"
)

// NewVcCmd builds the vc command, grouping verifiable-credential
// operations. With no subcommand it displays help.
func NewVcCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "vc",
		Short: "Manage verifiable credentials",
	}
	cmd.AddCommand(NewVcGetCmd())
	return cmd
}

// VcGetOpts ===============================================================================================================

// VcGetOpts holds vc get's flag values. It embeds RootOpts for Issuer,
// shared with every subcommand.
type VcGetOpts struct {
	RootOpts
	CredentialIdentifier      string
	CredentialConfigurationId string
	Key                       string
	User                      string
}

// NewVcGetOpts constructs a VcGetOpts.
func NewVcGetOpts() *VcGetOpts {
	return &VcGetOpts{}
}

// Run fetches a credential for o.User against o.Issuer, naming it by
// o.CredentialIdentifier (from authorization_details captured at login) or
// o.CredentialConfigurationId, proving possession of a holder key, and
// stores the result in the holder.
func (o *VcGetOpts) Run() error {
	w, err := holder.NewWallet(o.Issuer, o.User)
	if err != nil {
		return err
	}

	vc, err := w.GetCredential(o.Key, o.CredentialIdentifier)
	if err != nil {
		return err
	}

	fmt.Println(vc)
	return nil
}

// NewVcGetCmd builds the vc get command.
func NewVcGetCmd() *cobra.Command {
	opts := NewVcGetOpts()
	cmd := &cobra.Command{
		Use:   "get",
		Short: "Fetch a verifiable credential",
		RunE: func(cmd *cobra.Command, args []string) error {
			return opts.Run()
		},
	}
	bindRootOpts(cmd, &opts.RootOpts)
	cmd.Flags().StringVar(&opts.CredentialIdentifier, "credential-identifier", "", "Credential identifier from authorization_details")
	cmd.Flags().StringVar(&opts.Key, "key", "", "Holder key name (defaults to the connection's default key)")
	cmd.Flags().StringVar(&opts.User, "user", "", "Username (default: the issuer's default user)")
	return cmd
}
