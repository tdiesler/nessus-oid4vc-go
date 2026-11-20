package common

import (
	"os"
	"testing"
)

func TestMain(m *testing.M) {

	HomeDir()

	os.Exit(m.Run())
}
