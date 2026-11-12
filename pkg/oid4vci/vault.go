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
