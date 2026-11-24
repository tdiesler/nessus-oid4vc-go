package main

import (
	"os"

	co "github.com/tdiesler/nessus-oid4vc-go/pkg/common"
)

func main() {

	if err := ensureDefaultVaultIssuer(); err != nil {
		co.ErrorE(err)
		os.Exit(1)
	}

	if err := NewRootCmd().Execute(); err != nil {
		co.ErrorE(err)
		os.Exit(1)
	}
}
