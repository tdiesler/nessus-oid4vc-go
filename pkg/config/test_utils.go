package config

import (
	"os"
	"path/filepath"
)

// SetupHomeDir discovers NESSUS_OID4VC_HOME as the repo root when not already set.
func SetupHomeDir() string {
	homeDir := os.Getenv("NESSUS_OID4VC_HOME")
	if homeDir == "" {
		dir, _ := os.Getwd()
		homeDir = filepath.Join(dir, "..", "..")
		_ = os.Setenv("NESSUS_OID4VC_HOME", homeDir)
	}
	return homeDir
}
