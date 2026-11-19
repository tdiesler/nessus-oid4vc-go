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

// SetupHomeDir discovers NESSUS_OID4VC_HOME as the repo root — the nearest
// ancestor of the working directory containing go.mod — when not already
// set. Walking up rather than assuming a fixed nesting depth keeps this
// working regardless of how deep the calling package sits (e.g. pkg/wallet
// vs. pkg/cmd/oid4vc).
func SetupHomeDir() string {
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
