package oid4vci

import (
	"fmt"
	"os"
	"testing"

	co "github.com/tdiesler/nessus-oid4vc-go/pkg/common"
)

// testIssuer is deliberately not the server's BaseURL: a real deployment's
// public issuer identity and its local bind address are two different
// things, and this exists partly to prove that distinction actually works.
const testIssuer = "https://oid4vci.test.local"

// authServer is this package's single running AuthorizationServer, exposed
// so tests can call it directly — the same way pkg/vault's tests call
// EntityAccessor/KeyValueAccessor directly on a native Vault token — rather
// than only ever reaching it through OAuthClient's HTTP calls.
var authServer *AuthorizationServer

func TestMain(m *testing.M) {
	co.InitLogging()

	cfg, err := co.GetAppConfig()
	if err != nil {
		co.ErrorE(err)
		os.Exit(1)
	}

	// Start once for the whole package: AuthorizationServer binds a fixed,
	// configured address (cfg.Oid4vci.Addr).
	as, err := StartTestIssuerServer(cfg.Oid4vciAddr)
	if err != nil {
		co.ErrorE(fmt.Errorf("cannot start AuthorizationServer: %w", err))
		os.Exit(1)
	}
	authServer = as.WithIssuer(testIssuer)
	defer func() {
		StopTestIssuerServer(as)
	}()

	os.Exit(m.Run())
}
