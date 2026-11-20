package oauth

import (
	"os"
	"testing"

	co "github.com/tdiesler/nessus-oid4vc-go/pkg/common"
)

func TestMain(m *testing.M) {

	co.HomeDir()

	os.Exit(m.Run())
}
