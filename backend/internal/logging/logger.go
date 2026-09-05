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
	_ = kylog.DeclareString("addr")
	_ = kylog.DeclareString("alias_id")
	_ = kylog.DeclareString("allowlist_count")
	_ = kylog.DeclareString("attempts")
	_ = kylog.DeclareString("base_url")
	_ = kylog.DeclareString("challenge_id")
	_ = kylog.DeclareString("checkpoint")
	_ = kylog.DeclareString("client_iterations")
	_ = kylog.DeclareString("configured_keywords")
	_ = kylog.DeclareString("deferred")
	_ = kylog.DeclareString("deferred_rate_limited")
	_ = kylog.DeclareString("deliveries")
	_ = kylog.DeclareString("detail")
	_ = kylog.DeclareString("dir")
	_ = kylog.DeclareString("domain")
	_ = kylog.DeclareString("dst")
	_ = kylog.DeclareString("effect")
	_ = kylog.DeclareString("enrolled")
	_ = kylog.DeclareString("failed")
	_ = kylog.DeclareString("fetched")
	_ = kylog.DeclareString("fetched_through")
	_ = kylog.DeclareString("field")
	_ = kylog.DeclareString("fingerprint")
	_ = kylog.DeclareString("hard_cap")
	_ = kylog.DeclareString("header")
	_ = kylog.DeclareString("header_reports")
	_ = kylog.DeclareString("id")
	_ = kylog.DeclareString("installed")
	_ = kylog.DeclareString("interval")
	_ = kylog.DeclareString("key_file")
	_ = kylog.DeclareString("keywords")
	_ = kylog.DeclareString("latest")
	_ = kylog.DeclareString("length")
	_ = kylog.DeclareString("limit")
	_ = kylog.DeclareString("mailbox")
	_ = kylog.DeclareString("message_keywords")
	_ = kylog.DeclareString("minimum")
	_ = kylog.DeclareString("paired_approver_devices")
	_ = kylog.DeclareString("panic")
	_ = kylog.DeclareString("peer")
	_ = kylog.DeclareString("pgp_fingerprint")
	_ = kylog.DeclareString("pickup_id")
	_ = kylog.DeclareString("platform")
	_ = kylog.DeclareString("prefix")
	_ = kylog.DeclareString("processed")
	_ = kylog.DeclareString("raw_label")
	_ = kylog.DeclareString("recipient_count")
	_ = kylog.DeclareString("recipient_index")
	_ = kylog.DeclareString("remedy")
	_ = kylog.DeclareString("removed")
	_ = kylog.DeclareString("removed_stale")
	_ = kylog.DeclareString("renamed_to")
	_ = kylog.DeclareString("role")
	_ = kylog.DeclareString("rules_matched")
	_ = kylog.DeclareString("scheme")
	_ = kylog.DeclareString("selected_label")
	_ = kylog.DeclareString("sent")
	_ = kylog.DeclareString("sent_saved")
	_ = kylog.DeclareString("sent_via")
	_ = kylog.DeclareString("skipped_seen")
	_ = kylog.DeclareString("slot")
	_ = kylog.DeclareString("smtp_host")
	_ = kylog.DeclareString("smtp_port")
	_ = kylog.DeclareString("source")
	_ = kylog.DeclareString("src")
	_ = kylog.DeclareString("stage")
	_ = kylog.DeclareString("subscriber_id")
	_ = kylog.DeclareString("subscriptions")
	_ = kylog.DeclareString("table")
	_ = kylog.DeclareString("uid")
	_ = kylog.DeclareString("unhealthy_for_seconds")
	_ = kylog.DeclareString("username")
	_ = kylog.DeclareString("users_cleared_this_boot")
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
	if key == "raw_label" || (key == "addr" && strings.Contains(value, "@")) {
		return "[REDACTED]"
	}
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
