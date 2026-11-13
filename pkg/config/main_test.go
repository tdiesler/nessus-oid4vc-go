package config

import (
	"os"
	"testing"
)

// TestMain discovers NESSUS_OID4VC_HOME as the repo root when not already set,
// so config loading finds config/oid4vc-config.yml regardless of the working
// directory `go test` runs in.
func TestMain(m *testing.M) {

	SetupHomeDir()

	os.Exit(m.Run())
}
