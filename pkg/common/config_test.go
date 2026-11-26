package common

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestAppConfigLoading(t *testing.T) {
	cfg, err := GetAppConfig()
	require.NoError(t, err)
	require.Equal(t, "http://192.168.0.30:30820", cfg.VaultAddr)
	require.NotEmptyf(t, cfg.RootToken, "no root token")
	require.Equal(t, "oid4vc-client", cfg.OidcClient)
	require.Equal(t, "oid4vc", cfg.OidcProvider)
	require.Equal(t, "http://localhost:8400/callback", cfg.RedirectUri)
	require.Equal(t, "http://127.0.0.1:9000", cfg.Oid4vciAddr)

	claims := []string{"id", "email", "firstName", "familyName"}
	require.Equal(t, []CredentialConfig{
		{Id: "natural_person_sd", Format: "dc+sd-jwt", Vct: "NaturalPerson", Claims: claims},
		{Id: "natural_person_jwt", Format: "jwt_vc_json", Vct: "NaturalPerson", Claims: claims},
	}, cfg.CredentialConfigurations)
	require.Equal(t, []ScopeConfig{
		{Name: "natural_person", CredentialConfigurationIds: []string{"natural_person_sd", "natural_person_jwt"}},
	}, cfg.Scopes)
}

func TestValidateCredentialConfigurations(t *testing.T) {
	validConfig := CredentialConfig{Id: "natural_person_sd", Format: "dc+sd-jwt", Vct: "NaturalPerson"}

	cases := []struct {
		name      string
		cfg       AppConfig
		wantError string
	}{
		{
			name: "valid",
			cfg: AppConfig{
				CredentialConfigurations: []CredentialConfig{validConfig},
				Scopes:                   []ScopeConfig{{Name: "natural_person", CredentialConfigurationIds: []string{"natural_person_sd"}}},
			},
		},
		{
			name:      "duplicate credential configuration id",
			cfg:       AppConfig{CredentialConfigurations: []CredentialConfig{validConfig, validConfig}},
			wantError: `duplicate id "natural_person_sd"`,
		},
		{
			name:      "credential configuration missing format",
			cfg:       AppConfig{CredentialConfigurations: []CredentialConfig{{Id: "x", Vct: "X"}}},
			wantError: "format is required",
		},
		{
			name: "duplicate scope name",
			cfg: AppConfig{
				CredentialConfigurations: []CredentialConfig{validConfig},
				Scopes: []ScopeConfig{
					{Name: "natural_person", CredentialConfigurationIds: []string{"natural_person_sd"}},
					{Name: "natural_person", CredentialConfigurationIds: []string{"natural_person_sd"}},
				},
			},
			wantError: `duplicate name "natural_person"`,
		},
		{
			name: "scope references undeclared credential configuration id",
			cfg: AppConfig{
				CredentialConfigurations: []CredentialConfig{validConfig},
				Scopes:                   []ScopeConfig{{Name: "natural_person", CredentialConfigurationIds: []string{"does_not_exist"}}},
			},
			wantError: `undeclared credential_configuration_id "does_not_exist"`,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := c.cfg.validateCredentialConfigurations()
			if c.wantError == "" {
				require.NoError(t, err)
			} else {
				require.ErrorContains(t, err, c.wantError)
			}
		})
	}
}
