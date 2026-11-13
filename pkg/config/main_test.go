package config

import (
	"os"
	"testing"
)

func TestMain(m *testing.M) {

	SetupHomeDir()

	os.Exit(m.Run())
}
