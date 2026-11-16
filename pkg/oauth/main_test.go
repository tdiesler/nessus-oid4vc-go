package oauth

import (
	"os"
	"testing"

	co "github.com/tdiesler/nessus-oid4vc-go/pkg/common"
)

func TestMain(m *testing.M) {

	co.SetupHomeDir()

	os.Exit(m.Run())
}
