package config

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/viper"
)

type AppConfig struct {
	VaultAddr    string
	RootToken    string
	OIDCProvider string
}

func NewAppConfig() (*AppConfig, error) {

	v := viper.New()
	v.SetConfigFile(configFile())
	if err := v.ReadInConfig(); err != nil {
		return nil, fmt.Errorf("config: read %s: %w", v.ConfigFileUsed(), err)
	}

	if err := v.BindEnv("Vault.Addr", "VAULT_ADDR"); err != nil {
		return nil, err
	}
	if err := v.BindEnv("Vault.RootToken", "VAULT_ROOT_TOKEN"); err != nil {
		return nil, err
	}

	appcfg := &AppConfig{
		VaultAddr:    v.GetString("Vault.Addr"),
		RootToken:    v.GetString("Vault.RootToken"),
		OIDCProvider: v.GetString("Vault.OIDCProvider"),
	}
	if appcfg.VaultAddr == "" {
		return nil, fmt.Errorf("config: Vault.Addr is required (set it in %s or VAULT_ADDR)", v.ConfigFileUsed())
	}
	return appcfg, nil
}

func GetAppConfig() (*AppConfig, error) {
	if appConfig == nil {
		appcfg, err := NewAppConfig()
		if err != nil {
			return nil, err
		}
		appConfig = appcfg
	}
	return appConfig, nil
}

// Private -------------------------------------------------------------------------------------------------------------

var appConfig *AppConfig

// configFile returns the config file path: config/oid4vc-config.yml under
// NESSUS_OID4VC_HOME, falling back to the process' working directory when unset.
func configFile() string {
	return filepath.Join(os.Getenv("NESSUS_OID4VC_HOME"), "config", "oid4vc-config.yml")
}
