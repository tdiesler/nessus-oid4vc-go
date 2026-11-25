package common

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/viper"
)

type AppConfig struct {
	VaultAddr string
	RootToken string

	OidcClient   string
	OidcProvider string
	RedirectUri  string

	Oid4vciAddr string

	CredentialConfigurations []CredentialConfig
	Scopes                   []ScopeConfig
}

func NewAppConfig() (*AppConfig, error) {

	v := viper.New()
	v.SetConfigFile(configFile())
	if err := v.ReadInConfig(); err != nil {
		return nil, fmt.Errorf("common: read %s: %w", v.ConfigFileUsed(), err)
	}

	// NESSUS_OID4VC_ is this project's own env var prefix: any common key
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

	cfg := &AppConfig{
		VaultAddr:    v.GetString("Vault.Addr"),
		RootToken:    v.GetString("Vault.RootToken"),
		OidcClient:   v.GetString("Vault.OIDCClient"),
		OidcProvider: v.GetString("Vault.OIDCProvider"),
		RedirectUri:  v.GetString("Vault.RedirectURI"),
		Oid4vciAddr:  v.GetString("Oid4vci.Addr"),
	}
	if cfg.VaultAddr == "" {
		return nil, fmt.Errorf("Vault.Addr is required (set it in %s or VAULT_ADDR)", v.ConfigFileUsed())
	}

	// Credential configurations and their granting scopes.
	if err := v.UnmarshalKey("CredentialConfigurations", &cfg.CredentialConfigurations); err != nil {
		return nil, fmt.Errorf("common: decode CredentialConfigurations: %w", err)
	}
	if err := v.UnmarshalKey("Scopes", &cfg.Scopes); err != nil {
		return nil, fmt.Errorf("common: decode Scopes: %w", err)
	}
	if err := cfg.validateCredentialConfigurations(); err != nil {
		return nil, err
	}

	return cfg, nil
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

// validateCredentialConfigurations checks cfg's CredentialConfigurations
// and Scopes for internal consistency: unique, non-empty credential
// configuration ids and scope names, and every scope's
// CredentialConfigurationIds resolving to a declared credential
// configuration.
func (cfg *AppConfig) validateCredentialConfigurations() error {

	ids := make(map[string]bool, len(cfg.CredentialConfigurations))
	for _, cc := range cfg.CredentialConfigurations {
		if cc.Id == "" {
			return fmt.Errorf("common: CredentialConfigurations: id is required")
		}
		if ids[cc.Id] {
			return fmt.Errorf("common: CredentialConfigurations: duplicate id %q", cc.Id)
		}
		if cc.Format == "" {
			return fmt.Errorf("common: CredentialConfigurations[%s]: format is required", cc.Id)
		}
		if cc.Vct == "" {
			return fmt.Errorf("common: CredentialConfigurations[%s]: vct is required", cc.Id)
		}
		ids[cc.Id] = true
	}

	names := make(map[string]bool, len(cfg.Scopes))
	for _, scope := range cfg.Scopes {
		if scope.Name == "" {
			return fmt.Errorf("common: Scopes: name is required")
		}
		if names[scope.Name] {
			return fmt.Errorf("common: Scopes: duplicate name %q", scope.Name)
		}
		if len(scope.CredentialConfigurationIds) == 0 {
			return fmt.Errorf("common: Scopes[%s]: at least one credential_configuration_id is required", scope.Name)
		}
		for _, id := range scope.CredentialConfigurationIds {
			if !ids[id] {
				return fmt.Errorf("common: Scopes[%s]: undeclared credential_configuration_id %q", scope.Name, id)
			}
		}
		names[scope.Name] = true
	}

	return nil
}

// configFile returns the config file path: common/oid4vc-config.yml under
// NESSUS_OID4VC_HOME, falling back to the process' working directory when unset.
func configFile() string {
	return filepath.Join(os.Getenv("NESSUS_OID4VC_HOME"), "config", "oid4vc-config.yml")
}

// Functions -----------------------------------------------------------------------------------------------------------

// HomeDir discovers NESSUS_OID4VC_HOME as the repo root — the nearest
// ancestor of the working directory containing go.mod.
func HomeDir() string {
	homeDir := os.Getenv("NESSUS_OID4VC_HOME")
	if homeDir == "" {
		dir, _ := os.Getwd()
		for {
			if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
				break
			}
			parent := filepath.Dir(dir)
			if parent == dir {
				break
			}
			dir = parent
		}
		homeDir = dir
		_ = os.Setenv("NESSUS_OID4VC_HOME", homeDir)
	}
	return homeDir
}
