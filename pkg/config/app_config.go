package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/viper"
)

type AppConfig struct {
	VaultAddr    string
	RootToken    string
	OidcClient   string
	OidcProvider string
	RedirectURI  string
}

func NewAppConfig() (*AppConfig, error) {

	v := viper.New()
	v.SetConfigFile(configFile())
	if err := v.ReadInConfig(); err != nil {
		return nil, fmt.Errorf("config: read %s: %w", v.ConfigFileUsed(), err)
	}

	// NESSUS_OID4VC_ is this project's own env var prefix: any config key
	// picks up a matching env var automatically (e.g. Vault.OIDCClientID ->
	// NESSUS_OID4VC_VAULT_OIDCCLIENTID), no per-field binding needed.
	v.SetEnvPrefix("NESSUS_OID4VC")
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	v.AutomaticEnv()

	// Vault.Addr/RootToken instead follow Vault's own CLI env var
	// conventions, so existing VAULT_ADDR/VAULT_ROOT_TOKEN keep working.
	if err := v.BindEnv("Vault.Addr", "VAULT_ADDR"); err != nil {
		return nil, err
	}
	if err := v.BindEnv("Vault.RootToken", "VAULT_ROOT_TOKEN"); err != nil {
		return nil, err
	}

	// OIDC provider/client registration.
	v.SetDefault("Vault.OIDCProvider", "oid4vc")
	v.SetDefault("Vault.RedirectURI", "http://localhost:8400/callback")

	appcfg := &AppConfig{
		VaultAddr:    v.GetString("Vault.Addr"),
		RootToken:    v.GetString("Vault.RootToken"),
		OidcClient:   v.GetString("Vault.OIDCClient"),
		OidcProvider: v.GetString("Vault.OIDCProvider"),
		RedirectURI:  v.GetString("Vault.RedirectURI"),
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
