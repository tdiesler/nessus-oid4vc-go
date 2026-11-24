package main

import (
	"os"
	"os/signal"
	"syscall"

	co "github.com/tdiesler/nessus-oid4vc-go/pkg/common"
	"github.com/tdiesler/nessus-oid4vc-go/pkg/oid4vci"
)

func main() {

	as, err := oid4vci.NewAuthorizationServerFromConfig()
	if err != nil {
		co.ErrorE(err)
		os.Exit(1)
	}
	if err := as.Start(); err != nil {
		co.ErrorE(err)
		os.Exit(1)
	}
	co.InfoF("oid4vci AuthorizationServer listening on %s", as.BaseURL)

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	<-sigCh

	co.InfoF("oid4vci AuthorizationServer shutting down")
	if err := as.Shutdown(); err != nil {
		co.ErrorE(err)
		os.Exit(1)
	}
}
