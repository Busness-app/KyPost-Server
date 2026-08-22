package logging

import (
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
)

type Logger struct {
	logger *slog.Logger
	writer *rotatingWriter
}

func New(logDir string) (*Logger, error) {
	if err := os.MkdirAll(logDir, 0o755); err != nil {
		return nil, err
	}
	// A logger that cannot open its file is a failed dependency, not a
	// degraded one: this is the log operators read after an incident, and
	// slog silently discards write errors, so nothing downstream would ever
	// notice the absence.
	w, err := newRotatingWriter(filepath.Join(logDir, "app.log"), 16*1024*1024, 8)
	if err != nil {
		return nil, err
	}
	mw := io.MultiWriter(os.Stdout, w)
	return &Logger{
		logger: slog.New(slog.NewTextHandler(mw, nil)),
		writer: w,
	}, nil
}

func (l *Logger) Close() error {
	return l.writer.Close()
}

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
