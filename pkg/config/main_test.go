package config

import (
	"os"
	"path/filepath"
	"testing"
)

// TestMain discovers NESSUS_OID4VC_HOME as the repo root when not already set,
// so config loading finds config/oid4vc-config.yml regardless of the working
// directory `go test` runs in.
func TestMain(m *testing.M) {
	if os.Getenv("NESSUS_OID4VC_HOME") == "" {
		dir, _ := os.Getwd()
		_ = os.Setenv("NESSUS_OID4VC_HOME", filepath.Join(dir, "..", ".."))
	}
	os.Exit(m.Run())
}
