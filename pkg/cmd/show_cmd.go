package cmd

import (
	"encoding/json"
	"fmt"

	"github.com/spf13/cobra"
	co "github.com/tdiesler/nessus-oid4vc-go/pkg/common"
	"github.com/tdiesler/nessus-oid4vc-go/pkg/holder"
)

// NewShowCmd builds the show command, grouping read-only inspection of an
// issuer's published discovery documents and the wallet's own current
// state. With no subcommand it displays help.
func NewShowCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "show",
		Short: "Show discovery documents and wallet state",
	}
	cmd.AddCommand(NewShowCredentialIssuerMetadataCmd())
	cmd.AddCommand(NewShowOpenIDConfigurationCmd())
	cmd.AddCommand(NewShowStateCmd())
	return cmd
}

// ShowCredentialIssuerMetadataOpts =========================================================================================

// ShowCredentialIssuerMetadataOpts holds show credential-issuer-metadata's
// flag values. It embeds RootOpts for Issuer, shared with every subcommand.
type ShowCredentialIssuerMetadataOpts struct {
	RootOpts
}

// NewShowCredentialIssuerMetadataOpts constructs a ShowCredentialIssuerMetadataOpts.
func NewShowCredentialIssuerMetadataOpts() *ShowCredentialIssuerMetadataOpts {
	return &ShowCredentialIssuerMetadataOpts{}
}

// Run fetches o.Issuer's OID4VCI credential issuer metadata document and
// prints it as indented JSON.
func (o *ShowCredentialIssuerMetadataOpts) Run() error {
	metadata, err := holder.CredentialIssuerMetadata(o.Issuer)
	if err != nil {
		return err
	}
	return printJSON(metadata)
}

// NewShowCredentialIssuerMetadataCmd builds the show credential-issuer-metadata command.
func NewShowCredentialIssuerMetadataCmd() *cobra.Command {
	opts := NewShowCredentialIssuerMetadataOpts()
	cmd := &cobra.Command{
		Use:   "credential-issuer-metadata",
		Short: "Show the issuer's OID4VCI credential issuer metadata",
		RunE: func(cmd *cobra.Command, args []string) error {
			return opts.Run()
		},
	}
	bindRootOpts(cmd, &opts.RootOpts)
	return cmd
}

// ShowOpenIDConfigurationOpts ===============================================================================================

// ShowOpenIDConfigurationOpts holds show openid-configuration's flag
// values. It embeds RootOpts for Issuer, shared with every subcommand.
type ShowOpenIDConfigurationOpts struct {
	RootOpts
}

// NewShowOpenIDConfigurationOpts constructs a ShowOpenIDConfigurationOpts.
func NewShowOpenIDConfigurationOpts() *ShowOpenIDConfigurationOpts {
	return &ShowOpenIDConfigurationOpts{}
}

// Run fetches o.Issuer's OpenID Connect discovery document and prints it as
// indented JSON.
func (o *ShowOpenIDConfigurationOpts) Run() error {
	metadata, err := holder.OpenIDConfiguration(o.Issuer)
	if err != nil {
		return err
	}
	return printJSON(metadata)
}

// NewShowOpenIDConfigurationCmd builds the show openid-configuration command.
func NewShowOpenIDConfigurationCmd() *cobra.Command {
	opts := NewShowOpenIDConfigurationOpts()
	cmd := &cobra.Command{
		Use:   "openid-configuration",
		Short: "Show the issuer's OpenID Connect discovery document",
		RunE: func(cmd *cobra.Command, args []string) error {
			return opts.Run()
		},
	}
	bindRootOpts(cmd, &opts.RootOpts)
	return cmd
}

// ShowStateOpts =============================================================================================================

// ShowStateOpts holds show state's flag values. It embeds RootOpts for
// Issuer, shared with every subcommand.
type ShowStateOpts struct {
	RootOpts
}

// NewShowStateOpts constructs a ShowStateOpts.
func NewShowStateOpts() *ShowStateOpts {
	return &ShowStateOpts{}
}

// Run prints o.Issuer's alias and its default user as "issuer:user".
func (o *ShowStateOpts) Run() error {
	alias, username, err := holder.CurrentState(o.Issuer)
	if err != nil {
		return err
	}
	co.InfoF("%s:%s", alias, username)
	return nil
}

// NewShowStateCmd builds the show state command.
func NewShowStateCmd() *cobra.Command {
	opts := NewShowStateOpts()
	cmd := &cobra.Command{
		Use:   "state",
		Short: "Show the current issuer and user",
		RunE: func(cmd *cobra.Command, args []string) error {
			return opts.Run()
		},
	}
	bindRootOpts(cmd, &opts.RootOpts)
	return cmd
}

// Functions -----------------------------------------------------------------------------------------------------------

// printJSON prints v to stdout as indented JSON.
func printJSON(v any) error {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	fmt.Println(string(data))
	return nil
}
