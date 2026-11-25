package oauth

import (
	"os"
	"testing"

	co "github.com/tdiesler/nessus-oid4vc-go/pkg/common"
)

func TestMain(m *testing.M) {

	co.InitLogging()

	code := m.Run()
	os.Exit(code)
}
