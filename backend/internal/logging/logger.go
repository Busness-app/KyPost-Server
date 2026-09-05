package logging

import (
	kylog "github.com/Busness-app/ky-primitives/logging"
	"io"
	"log/slog"
	"strings"
)

// Logger adapts existing flat string fields to the suite's filtering handler.
type Logger struct{ logger *slog.Logger }

// New retains its directory argument for existing callers; the process writes
// only JSON to stderr. The supervisor owns capture and rotation.
func New(_ string) (*Logger, error) { return NewWithOutput(nil) }
func NewWithOutput(out io.Writer) (*Logger, error) {
	cfg, err := kylog.FromEnv()
	if err != nil {
		return nil, err
	}
	cfg.App = "kypost"
	cfg.Out = out
	logger, err := kylog.New(cfg)
	if err != nil {
		return nil, err
	}
	return &Logger{logger: slog.New(logger.Handler())}, nil
}
func (l *Logger) Handler() slog.Handler { return l.logger.Handler() }
func (l *Logger) Close() error          { return nil }

// Explicit product vocabulary. Unknown keys are dropped and counted by the
// library; declarations never come from a request or a call site's key string.
var (
	_ = kylog.DeclareString("error")
	_ = kylog.DeclareString("reason")
	_ = kylog.DeclareString("file")
	_ = kylog.DeclareString("path")
	_ = kylog.DeclareString("model")
	_ = kylog.DeclareString("mode")
	_ = kylog.DeclareString("port")
	_ = kylog.DeclareString("label")
	_ = kylog.DeclareString("attempt")
	_ = kylog.DeclareString("devices")
	_ = kylog.DeclareString("digest")
	_ = kylog.DeclareString("key_id")
	_ = kylog.DeclareString("message_id")
)

func (l *Logger) Info(msg string, kv ...string) {
	l.logger.Info(msg, stringsToArgs(kv)...)
}

func (l *Logger) Error(msg string, kv ...string) {
	l.logger.Error(msg, stringsToArgs(kv)...)
}

// stringsToArgs adapts the Logger.Info/Error flat-string-pairs API (kept for
// caller convenience — every call site already has string values) onto
// slog's ...any args.
func stringsToArgs(kv []string) []any {
	args := make([]any, 0, len(kv))
	for i := 0; i+1 < len(kv); i += 2 {
		args = append(args, kv[i], redactValue(kv[i], kv[i+1]))
	}
	return args
}

// redactValue keeps the Logger's convenient flat-string API from turning a
// call-site mistake into a cleartext disclosure. Keys are intentionally
// matched by meaning, not by an exhaustive list of current field names.
func redactValue(key, value string) string {
	normalized := strings.ToLower(strings.ReplaceAll(strings.ReplaceAll(key, "-", "_"), ".", "_"))
	for _, sensitive := range []string{
		"password", "secret", "token", "credential", "authorization", "cookie",
		"recipient", "email", "username", "subject", "body", "private_key", "api_key",
	} {
		if strings.Contains(normalized, sensitive) {
			return "[REDACTED]"
		}
	}
	return value
}
