package cmd

import (
	"encoding/json"
	"fmt"
	"sort"
	"strconv"

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
	cmd.AddCommand(NewShowLoginCmd())
	cmd.AddCommand(NewShowKeysCmd())
	cmd.AddCommand(NewShowVcsCmd())
	cmd.AddCommand(NewShowVcCmd())
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

// ShowLoginOpts =============================================================================================================

// ShowLoginOpts holds show login's flag values. It embeds RootOpts for
// Issuer, shared with every subcommand.
type ShowLoginOpts struct {
	RootOpts
}

// NewShowLoginOpts constructs a ShowLoginOpts.
func NewShowLoginOpts() *ShowLoginOpts {
	return &ShowLoginOpts{}
}

// Run prints o.Issuer's alias and its default user as "issuer:user".
func (o *ShowLoginOpts) Run() error {
	alias, username, err := holder.CurrentState(o.Issuer)
	if err != nil {
		return err
	}
	co.InfoF("%s:%s", alias, username)
	return nil
}

// NewShowLoginCmd builds the show login command.
func NewShowLoginCmd() *cobra.Command {
	opts := NewShowLoginOpts()
	cmd := &cobra.Command{
		Use:   "login",
		Short: "Show the current issuer and user",
		RunE: func(cmd *cobra.Command, args []string) error {
			return opts.Run()
		},
	}
	bindRootOpts(cmd, &opts.RootOpts)
	return cmd
}

// ShowKeysOpts ==============================================================================================================

// ShowKeysOpts holds show keys' flag values. It embeds RootOpts for Issuer,
// shared with every subcommand.
type ShowKeysOpts struct {
	RootOpts
	User string
}

// NewShowKeysOpts constructs a ShowKeysOpts.
func NewShowKeysOpts() *ShowKeysOpts {
	return &ShowKeysOpts{}
}

// Run prints o.User's holder key IDs for o.Issuer, one per line, marking
// the connection's default key.
func (o *ShowKeysOpts) Run() error {
	w, err := holder.NewWallet(o.Issuer, o.User)
	if err != nil {
		return err
	}

	conn, ok := w.Issuer().Users[w.Username()]
	if !ok || len(conn.Keys) == 0 {
		fmt.Println("no holder keys")
		return nil
	}
	for _, key := range conn.Keys {
		if key.KeyID == conn.DefaultKey {
			fmt.Printf("%s (default)\n", key.KeyID)
		} else {
			fmt.Println(key.KeyID)
		}
	}
	return nil
}

// NewShowKeysCmd builds the show keys command.
func NewShowKeysCmd() *cobra.Command {
	opts := NewShowKeysOpts()
	cmd := &cobra.Command{
		Use:   "keys",
		Short: "Show the current user's holder keys",
		RunE: func(cmd *cobra.Command, args []string) error {
			return opts.Run()
		},
	}
	bindRootOpts(cmd, &opts.RootOpts)
	cmd.Flags().StringVar(&opts.User, "user", "", "Username (default: the issuer's default user)")
	_ = cmd.RegisterFlagCompletionFunc("user", completeUsername)
	return cmd
}

// ShowVcsOpts ================================================================================================================

// ShowVcsOpts holds show vcs' flag values. It embeds RootOpts for Issuer,
// shared with every subcommand.
type ShowVcsOpts struct {
	RootOpts
	User string
}

// NewShowVcsOpts constructs a ShowVcsOpts.
func NewShowVcsOpts() *ShowVcsOpts {
	return &ShowVcsOpts{}
}

// Run prints o.User's stored credential identifiers for o.Issuer, as a
// 1-based numbered list — the same numbering "show vc" accepts.
func (o *ShowVcsOpts) Run() error {
	w, err := holder.NewWallet(o.Issuer, o.User)
	if err != nil {
		return err
	}

	conn, ok := w.Issuer().Users[w.Username()]
	if !ok || len(conn.Credentials) == 0 {
		fmt.Println("no stored credentials")
		return nil
	}
	for i, id := range sortedCredentialIdentifiers(conn) {
		fmt.Printf("%3d  %s\n", i+1, id)
	}
	return nil
}

// NewShowVcsCmd builds the show vcs command.
func NewShowVcsCmd() *cobra.Command {
	opts := NewShowVcsOpts()
	cmd := &cobra.Command{
		Use:   "vcs",
		Short: "Show the current user's stored verifiable credentials",
		RunE: func(cmd *cobra.Command, args []string) error {
			return opts.Run()
		},
	}
	bindRootOpts(cmd, &opts.RootOpts)
	cmd.Flags().StringVar(&opts.User, "user", "", "Username (default: the issuer's default user)")
	_ = cmd.RegisterFlagCompletionFunc("user", completeUsername)
	return cmd
}

// ShowVcOpts =================================================================================================================

// ShowVcOpts holds show vc's flag values. It embeds RootOpts for Issuer,
// shared with every subcommand.
type ShowVcOpts struct {
	RootOpts
	User     string
	Selector string
}

// NewShowVcOpts constructs a ShowVcOpts.
func NewShowVcOpts() *ShowVcOpts {
	return &ShowVcOpts{}
}

// Run prints the stored credential o.Selector names for o.User — either a
// 1-based index into "show vcs"'s numbered list, or a credential
// identifier directly — the same way vc get prints a freshly-fetched one.
func (o *ShowVcOpts) Run() error {
	w, err := holder.NewWallet(o.Issuer, o.User)
	if err != nil {
		return err
	}

	conn, ok := w.Issuer().Users[w.Username()]
	if !ok {
		return fmt.Errorf("no stored credentials")
	}

	identifier := o.Selector
	if n, err := strconv.Atoi(o.Selector); err == nil {
		ids := sortedCredentialIdentifiers(conn)
		if n < 1 || n > len(ids) {
			return fmt.Errorf("no credential numbered %d", n)
		}
		identifier = ids[n-1]
	}

	vc, ok := conn.Credentials[identifier]
	if !ok {
		return fmt.Errorf("no stored credential %q", identifier)
	}
	return printCredential(vc)
}

// NewShowVcCmd builds the show vc command.
func NewShowVcCmd() *cobra.Command {
	opts := NewShowVcOpts()
	cmd := &cobra.Command{
		Use:               "vc <number|identifier>",
		Short:             "Show a stored verifiable credential's details",
		Args:              cobra.ExactArgs(1),
		ValidArgsFunction: completeStoredCredentialIdentifier,
		RunE: func(cmd *cobra.Command, args []string) error {
			opts.Selector = args[0]
			return opts.Run()
		},
	}
	bindRootOpts(cmd, &opts.RootOpts)
	cmd.Flags().StringVar(&opts.User, "user", "", "Username (default: the issuer's default user)")
	_ = cmd.RegisterFlagCompletionFunc("user", completeUsername)
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

// sortedCredentialIdentifiers returns conn's stored credential identifiers,
// sorted — the same order and 1-based numbering "show vcs" displays and
// "show vc" accepts.
func sortedCredentialIdentifiers(conn *holder.Connection) []string {
	ids := make([]string, 0, len(conn.Credentials))
	for id := range conn.Credentials {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}
