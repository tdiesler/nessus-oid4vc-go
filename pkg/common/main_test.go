package common

import (
	"os"
	"testing"
)

func TestMain(m *testing.M) {
	HomeDir()

	code := m.Run()
	os.Exit(code)
}
