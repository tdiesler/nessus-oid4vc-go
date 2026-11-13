package oid4vci

import (
	"fmt"

	"github.com/hashicorp/vault/api"
	cfg "github.com/tdiesler/nessus-oid4vc-go/pkg/config"
)

// NewClient returns a fresh, unauthenticated Vault client pointing to config Vault.Addr
// (or the library default, driven by VAULT_ADDR, when addr is empty).
func NewClient() (*api.Client, error) {
	appcfg, err := cfg.GetAppConfig()
	if err != nil {
		return nil, err
	}
	apicfg := api.DefaultConfig()
	apicfg.Address = appcfg.VaultAddr
	return api.NewClient(apicfg)
}

// RootClient returns a Vault client authenticated with the local dev
// Vault's root token, fetched the same way scripts/vault-setup does.
func RootClient() (*api.Client, error) {

	client, err := NewClient()
	if err != nil {
		return nil, err
	}
	appcfg, err := cfg.GetAppConfig()
	if err != nil {
		return nil, err
	}
	if appcfg.RootToken == "" {
		return nil, fmt.Errorf("no root token")
	}
	client.SetToken(appcfg.RootToken)
	return client, nil
}

// DiscoverClientId provides general mapping from a client's name to its client_id.
func DiscoverClientId(clientName string) (string, error) {
	client, err := RootClient()
	if err != nil {
		return "", err
	}

	secret, err := client.Logical().Read("identity/oidc/client/" + clientName)
	if err != nil {
		return "", fmt.Errorf("read oidc client %q: %w", clientName, err)
	}
	if secret == nil {
		return "", fmt.Errorf("oidc client %q not found", clientName)
	}
	clientId, ok := secret.Data["client_id"].(string)
	if !ok || clientId == "" {
		return "", fmt.Errorf("oidc client %q has no client_id", clientName)
	}
	return clientId, nil
}

// DiscoverClientSecret provides general mapping from a client's name to its client_secret.
func DiscoverClientSecret(clientName string) (string, error) {
	client, err := RootClient()
	if err != nil {
		return "", err
	}

	secret, err := client.Logical().Read("identity/oidc/client/" + clientName)
	if err != nil {
		return "", fmt.Errorf("read oidc client %q: %w", clientName, err)
	}
	if secret == nil {
		return "", fmt.Errorf("oidc client %q not found", clientName)
	}
	clientSecret, ok := secret.Data["client_secret"].(string)
	if !ok || clientSecret == "" {
		return "", fmt.Errorf("oidc client %q has no client_secret", clientName)
	}
	return clientSecret, nil
}
