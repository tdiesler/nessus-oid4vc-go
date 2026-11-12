package logging

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"time"

	"gopkg.in/natefinch/lumberjack.v2"
)

const (
	LevelNoop  = slog.Level(-10)
	LevelDebug = slog.LevelDebug
	LevelInfo  = slog.LevelInfo
	LevelWarn  = slog.LevelWarn
	LevelError = slog.LevelError
	LevelFatal = slog.Level(10)
)

const (
	SymbolKey = "symbol"
	TraceKey  = "trace"
)

// InitLogging sets the default logger to write >= LevelInfo records to the
// console (stdout) and every record, regardless of level, to logfile
// (rotated via lumberjack).
func InitLogging(logfile string) Logger {
	console := slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		Level:       LevelInfo,
		ReplaceAttr: replaceAttr,
	})
	file := slog.NewJSONHandler(&lumberjack.Logger{Filename: logfile}, &slog.HandlerOptions{
		Level:       LevelDebug,
		ReplaceAttr: replaceAttr,
	})
	slog.SetDefault(slog.New(NewMultiHandler(console, file)))
	return Default()
}

func LogsDir() string {
	home := os.Getenv("NESSUS_OID4VC_HOME")
	if home == "" {
		home, _ = os.Getwd()
	}
	logsDir := home + "/workspace/logs"
	if err := os.MkdirAll(logsDir, 0744); err != nil {
		panic(err)
	}
	return logsDir
}

func Default() Logger {
	return &BaseLogger{slog.Default()}
}

func DebugF(format string, args ...any) { Default().DebugF(format, args...) }

func InfoF(format string, args ...any) { Default().InfoF(format, args...) }

func WarnF(format string, args ...any) { Default().WarnF(format, args...) }

func WarnE(err error) { Default().WarnE(err) }

func ErrorF(format string, args ...any) { Default().ErrorF(format, args...) }

func ErrorE(err error) { Default().ErrorE(err) }

// FatalF is an extension of ErrorF, which panics after writing the log message
func FatalF(format string, args ...any) { Default().FatalF(format, args...) }

func FatalE(err error) { Default().FatalE(err) }

func LogF(level slog.Level, format string, args ...any) {
	if level > LevelNoop {
		Default().LogF(level, format, args...)
	}
}

// GetStackFrames extracts the stack trace lines from a "%+v"-formatted
// error, skipping frames inside this file.
func GetStackFrames(err error) []string {
	buf := &strings.Builder{}
	_, _ = fmt.Fprintf(buf, "%+v", err)
	ignore := "pkg/logging/logging.go"
	stack := strings.Split(buf.String(), "\n")[1:]
	for len(stack) >= 2 && strings.Contains(stack[1], ignore) {
		stack = stack[2:]
	}
	frames := make([]string, len(stack))
	for n, fr := range stack {
		frames[n] = strings.TrimSpace(fr)
	}
	return frames
}

// Private -------------------------------------------------------------------------------------------------------------

func replaceAttr(_ []string, a slog.Attr) slog.Attr {
	switch {
	case a.Key == slog.TimeKey:
		a = slog.String(slog.TimeKey, a.Value.Time().UTC().Format(time.DateTime))
	case a.Key == slog.LevelKey && a.Value.Equal(slog.AnyValue(LevelFatal)):
		a = slog.String(slog.LevelKey, "FATAL")
	case a.Key == slog.LevelKey && a.Value.Equal(slog.AnyValue(LevelNoop)):
		a = slog.String(slog.LevelKey, "NOOP")
	}
	return a
}

// Logger --------------------------------------------------------------------------------------------------------------

type Logger interface {
	DebugF(format string, args ...any)
	InfoF(format string, args ...any)
	WarnF(format string, args ...any)
	WarnE(err error)
	ErrorF(format string, args ...any)
	ErrorE(err error)
	FatalF(format string, args ...any)
	FatalE(err error)
	LogF(level slog.Level, format string, args ...any)
	LogE(level slog.Level, err error)
	With(args ...any) Logger
}

type BaseLogger struct {
	slgr *slog.Logger
}

func (bl *BaseLogger) With(args ...any) Logger {
	return &BaseLogger{bl.slgr.With(args...)}
}

func (bl *BaseLogger) DebugF(format string, args ...any) {
	bl.LogF(LevelDebug, format, args...)
}

func (bl *BaseLogger) InfoF(format string, args ...any) {
	bl.LogF(LevelInfo, format, args...)
}

func (bl *BaseLogger) WarnF(format string, args ...any) {
	bl.LogF(LevelWarn, format, args...)
}

func (bl *BaseLogger) WarnE(err error) {
	bl.LogE(LevelWarn, err)
}

func (bl *BaseLogger) ErrorF(format string, args ...any) {
	bl.LogF(LevelError, format, args...)
}

// ErrorE logs the error message to the console (if >= Info) and the file,
// plus its stack trace as a single attribute in the file's JSON output.
func (bl *BaseLogger) ErrorE(err error) {
	bl.LogE(LevelError, err)
}

// FatalF is an extension of ErrorF, which panics after writing the log message
func (bl *BaseLogger) FatalF(format string, args ...any) {
	bl.LogF(LevelFatal, format, args...)
	panic(fmt.Sprintf(format, args...))
}

func (bl *BaseLogger) FatalE(err error) {
	bl.LogE(LevelFatal, err)
	panic(err)
}

func (bl *BaseLogger) LogF(level slog.Level, format string, args ...any) {
	bl.slgr.Log(context.Background(), level, fmt.Sprintf(format, args...))
}

func (bl *BaseLogger) LogE(level slog.Level, err error) {
	bl.slgr.Log(context.Background(), level, err.Error(), slog.Any(TraceKey, GetStackFrames(err)))
}

// MultiHandler fans a record out to every handler that has it enabled, so
// different sinks (console, file) can each apply their own level filter.
type MultiHandler struct {
	handlers []slog.Handler
}

func NewMultiHandler(handlers ...slog.Handler) *MultiHandler {
	return &MultiHandler{handlers: handlers}
}

func (m *MultiHandler) Enabled(ctx context.Context, level slog.Level) bool {
	for _, h := range m.handlers {
		if h.Enabled(ctx, level) {
			return true
		}
	}
	return false
}

func (m *MultiHandler) Handle(ctx context.Context, r slog.Record) error {
	for _, h := range m.handlers {
		if h.Enabled(ctx, r.Level) {
			if err := h.Handle(ctx, r.Clone()); err != nil {
				return err
			}
		}
	}
	return nil
}

func (m *MultiHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	next := make([]slog.Handler, len(m.handlers))
	for i, h := range m.handlers {
		next[i] = h.WithAttrs(attrs)
	}
	return &MultiHandler{handlers: next}
}

func (m *MultiHandler) WithGroup(name string) slog.Handler {
	next := make([]slog.Handler, len(m.handlers))
	for i, h := range m.handlers {
		next[i] = h.WithGroup(name)
	}
	return &MultiHandler{handlers: next}
}
