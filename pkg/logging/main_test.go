package logging

import (
	"os"
	"testing"

	"github.com/tdiesler/nessus-oid4vc-go/pkg/config"
)

func TestMain(m *testing.M) {

	config.SetupHomeDir()

	os.Exit(m.Run())
}
