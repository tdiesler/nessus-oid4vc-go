package logging

import (
	"fmt"
	"testing"

	"github.com/pkg/errors"
)

func TestBasicLog(t *testing.T) {

	logfile := LogsDir() + "/test.log"
	InitLogging(logfile)

	DebugF("Debug %s", "Kermit")
	InfoF("Info %s", "Kermit")
	WarnF("Warn %s", "Kermit")
	ErrorF("Error %s", "Kermit")

	LogF(LevelInfo, "LevelInfo %s", "Kermit")
}

func TestSymbolLog(t *testing.T) {

	logfile := LogsDir() + "/test.log"
	log := InitLogging(logfile)

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

	logfile := LogsDir() + "/test.log"
	InitLogging(logfile)

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

func TestLevelFatal(t *testing.T) {

	// Run manually
	t.SkipNow()

	logfile := LogsDir() + "/test.log"
	InitLogging(logfile)

	//FatalF("Fatal %s", "Kermit")

	err := errors.Errorf("FatalError %s", "Kermit")
	//FatalE(err)

	FatalE(errors.Wrapf(err, "Wrapped error"))
}
