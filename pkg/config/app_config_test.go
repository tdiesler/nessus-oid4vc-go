package config

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestAppConfigLoading(t *testing.T) {
	cfg, err := GetAppConfig()
	require.NoError(t, err)
	require.Equal(t, "http://192.168.0.30:30820", cfg.VaultAddr)
	require.NotEmptyf(t, cfg.RootToken, "no root token")
	require.Equal(t, "oid4vc", cfg.OIDCProvider)
}
