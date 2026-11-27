package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
	"github.com/tdiesler/nessus-oid4vc-go/pkg/holder"
)

// Functions ---------------------------------------------------------------------------------------------------------

// completeClientId offers cmd's resolved issuer's previously-used OAuth
// client IDs (its default client, plus any seen on an existing user
// connection) as completions for --client — a list of known values, not
// every client ID the issuer would actually accept.
func completeClientId(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
	issuer, err := resolveCompletionIssuer(cmd)
	if err != nil {
		return nil, cobra.ShellCompDirectiveNoFileComp
	}

	seen := make(map[string]bool)
	var clients []string
	if issuer.DefaultClient != "" {
		clients = append(clients, issuer.DefaultClient)
		seen[issuer.DefaultClient] = true
	}
	for _, conn := range issuer.Users {
		if conn.ClientId != "" && !seen[conn.ClientId] {
			clients = append(clients, conn.ClientId)
			seen[conn.ClientId] = true
		}
	}
	return clients, cobra.ShellCompDirectiveNoFileComp
}

// completeCredentialIdentifier offers cmd's resolved user's credential
// identifiers — captured in authorization_details at login — as
// completions for --credential-identifier.
func completeCredentialIdentifier(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
	conn, err := resolveCompletionConnection(cmd)
	if err != nil {
		return nil, cobra.ShellCompDirectiveNoFileComp
	}

	var ids []string
	for _, detail := range conn.AuthorizationDetails {
		ids = append(ids, detail.CredentialIdentifiers...)
	}
	return ids, cobra.ShellCompDirectiveNoFileComp
}

// completeHolderKey offers cmd's resolved user's holder key names as
// completions for --key.
func completeHolderKey(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
	conn, err := resolveCompletionConnection(cmd)
	if err != nil {
		return nil, cobra.ShellCompDirectiveNoFileComp
	}

	keys := make([]string, 0, len(conn.Keys))
	for _, key := range conn.Keys {
		keys = append(keys, key.KeyID)
	}
	return keys, cobra.ShellCompDirectiveNoFileComp
}

// completeIssuerAlias offers the holder's configured issuer aliases as
// completions for --issuer.
func completeIssuerAlias(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
	state, err := holder.LoadWalletState()
	if err != nil {
		return nil, cobra.ShellCompDirectiveNoFileComp
	}

	aliases := make([]string, 0, len(state.Issuers))
	for alias := range state.Issuers {
		aliases = append(aliases, alias)
	}
	return aliases, cobra.ShellCompDirectiveNoFileComp
}

// completeScope offers cmd's resolved issuer's supported OAuth scopes,
// fetched live from its OID4VCI credential issuer metadata, as completions
// for --scope.
func completeScope(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
	alias, _ := cmd.Flags().GetString("issuer")
	metadata, err := holder.CredentialIssuerMetadata(alias)
	if err != nil {
		return nil, cobra.ShellCompDirectiveNoFileComp
	}

	seen := make(map[string]bool)
	var scopes []string
	for _, cc := range metadata.CredentialConfigurationsSupported {
		if cc.Scope != "" && !seen[cc.Scope] {
			scopes = append(scopes, cc.Scope)
			seen[cc.Scope] = true
		}
	}
	return scopes, cobra.ShellCompDirectiveNoFileComp
}

// completeUsername offers cmd's resolved issuer's known usernames as
// completions for --user.
func completeUsername(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
	issuer, err := resolveCompletionIssuer(cmd)
	if err != nil {
		return nil, cobra.ShellCompDirectiveNoFileComp
	}

	users := make([]string, 0, len(issuer.Users))
	for user := range issuer.Users {
		users = append(users, user)
	}
	return users, cobra.ShellCompDirectiveNoFileComp
}

// resolveCompletionConnection resolves cmd's --issuer and --user flags
// (already parsed by cobra by the time a flag completion func runs) to
// that issuer's connection for that user, the same way holder.NewWallet
// resolves them for a real run, without creating one if it doesn't exist.
func resolveCompletionConnection(cmd *cobra.Command) (*holder.Connection, error) {
	issuer, err := resolveCompletionIssuer(cmd)
	if err != nil {
		return nil, err
	}

	username, _ := cmd.Flags().GetString("user")
	if username == "" {
		username = issuer.DefaultUser
	}
	conn, ok := issuer.Users[username]
	if !ok {
		return nil, fmt.Errorf("no connection for user %q", username)
	}
	return conn, nil
}

// resolveCompletionIssuer resolves cmd's --issuer flag (already parsed by
// cobra by the time a flag completion func runs) to its configured Issuer,
// falling back to the holder's default issuer the same way bindRootOpts'
// --issuer help text describes.
func resolveCompletionIssuer(cmd *cobra.Command) (*holder.Issuer, error) {
	state, err := holder.LoadWalletState()
	if err != nil {
		return nil, err
	}

	alias, _ := cmd.Flags().GetString("issuer")
	if alias == "" {
		alias = state.DefaultIssuer
	}
	issuer, ok := state.Issuers[alias]
	if !ok {
		return nil, fmt.Errorf("no issuer %q configured", alias)
	}
	return issuer, nil
}
