package vault

import (
	"fmt"

	"github.com/hashicorp/vault/api"
	co "github.com/tdiesler/nessus-oid4vc-go/pkg/common"
)

// NewClient returns a fresh, unauthenticated Vault client pointing to common Vault.Addr
// (or the library default, driven by VAULT_ADDR, when addr is empty).
func NewClient(token ...string) (*api.Client, error) {
	cfg, err := co.GetAppConfig()
	if err != nil {
		return nil, err
	}
	apicfg := api.DefaultConfig()
	apicfg.Address = cfg.VaultAddr
	client, err := api.NewClient(apicfg)
	if err != nil {
		return nil, err
	}
	if len(token) > 0 {
		client.SetToken(token[0])
	}
	return client, nil
}

// RootClient returns a Vault client authenticated with the local dev
// Vault's root token, fetched the same way scripts/vault-setup does.
func RootClient() (*api.Client, error) {
	cfg, err := co.GetAppConfig()
	if err != nil {
		return nil, err
	}
	if cfg.RootToken == "" {
		return nil, fmt.Errorf("no root token")
	}
	return NewClient(cfg.RootToken)
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
