package common

import (
	"fmt"
	"testing"

	"github.com/pkg/errors"
)

func TestBasicLog(t *testing.T) {

	InitLogging()

	DebugF("Debug %s", "Kermit")
	InfoF("Info %s", "Kermit")
	WarnF("Warn %s", "Kermit")
	ErrorF("Error %s", "Kermit")

	LogF(LevelInfo, "LevelInfo %s", "Kermit")
}

func TestSymbolLog(t *testing.T) {
	log := InitLogging()
	log = log.With(SymbolKey, "nexo/btc")
	log.InfoF("Info %s", "Kermit")
}

func TestErrorPrint(t *testing.T) {

	fmt.Printf("------\n")
	err := errors.New("This is an error")
	fmt.Printf("%+v\n", err)

	fmt.Printf("------\n")
	fmt.Printf("%+v\n", errors.Wrapf(err, "Wrapped error"))
}

func TestErrorLog(t *testing.T) {

	InitLogging()

	InfoF("---")
	ErrorF("message error%02d", 1)

	InfoF("---")
	ErrorE(fmt.Errorf("no stack trace error02"))

	InfoF("---")
	ErrorE(errors.Errorf("Stack trace error03"))

	InfoF("---")
	innerErr := errors.Errorf("Inner error")
	outerErr := errors.Wrap(innerErr, "Outer error")
	ErrorE(outerErr)
}
