package common

import (
	"os"
	"path/filepath"
)

// Fixed by scripts/vault-setup's holder persona.
const (
	UserAlice    = "alice"
	UserMax      = "max"
	UserPassword = "password"
)

// SetupHomeDir discovers NESSUS_OID4VC_HOME as the repo root when not already set.
func SetupHomeDir() string {
	homeDir := os.Getenv("NESSUS_OID4VC_HOME")
	if homeDir == "" {
		workdir, _ := os.Getwd()
		homeDir = filepath.Join(workdir, "..", "..")
		_ = os.Setenv("NESSUS_OID4VC_HOME", homeDir)
	}
	return homeDir
}
