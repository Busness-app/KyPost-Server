package processor

import (
	"strings"
	"testing"

	"github.com/Busness-app/kypost-server/backend/internal/config"
	"github.com/Busness-app/kypost-server/backend/internal/logging"
	"github.com/Busness-app/kypost-server/backend/internal/redaction"
)

// newRedactionPoller builds the minimum Poller UpdateConfig touches: a config,
// a compiled redaction engine and a logger.
func newRedactionPoller(t *testing.T) *Poller {
	t.Helper()
	logger, err := logging.New(t.TempDir())
	if err != nil {
		t.Fatalf("logging.New: %v", err)
	}
	t.Cleanup(func() { _ = logger.Close() })

	base := config.Default()
	engine, err := redaction.New(base.Redaction.Patterns)
	if err != nil {
		t.Fatalf("redaction.New: %v", err)
	}
	return &Poller{log: logger, cfg: base, redaction: engine}
}

// UpdateConfig must refuse a config whose redaction patterns do not compile
// rather than committing it. Committing recorded the broken set as current, so
// every later diff said "unchanged", the rebuild never retried, and redaction
// silently kept enforcing the OLD set while the API reported the new one as
// live — a privacy control failing open and quietly. The guard exists in
// UpdateConfig and had no regression test.
func TestUpdateConfigRefusesNonCompilingRedactionPatterns(t *testing.T) {
	p := newRedactionPoller(t)

	bad := config.Default()
	// Marker field: shows whether the whole config was swapped, not just
	// whether the engine was rebuilt.
	bad.Timezone = "Etc/UTC"
	bad.Redaction.Patterns = []config.Pattern{
		{Name: "broken", Regex: "([unclosed", Replacement: "[X]"},
	}

	p.UpdateConfig(bad)

	if got := p.currentConfig().Timezone; got == "Etc/UTC" {
		t.Fatal("UpdateConfig committed a config whose redaction patterns do not compile; " +
			"the broken set then reads as current, the rebuild never retries, and redaction fails open")
	}
	// The engine must still be the previous, working one.
	if got := p.currentRedaction().Apply("contact me at yoshi@urlxl.com"); !strings.Contains(got, "[REDACTED_EMAIL]") {
		t.Fatalf("redaction stopped working after a refused update: Apply(...) = %q", got)
	}
}

// The counterpart: a valid pattern change must actually take effect. Guards
// the original bug the refusal path was bolted onto — edits to redaction
// patterns never took effect until restart.
func TestUpdateConfigAppliesValidRedactionPatternChange(t *testing.T) {
	p := newRedactionPoller(t)

	next := config.Default()
	next.Redaction.Patterns = []config.Pattern{
		{Name: "ticket", Regex: `TICKET-\d+`, Replacement: "[REDACTED_TICKET]"},
	}

	p.UpdateConfig(next)

	got := p.currentRedaction().Apply("see TICKET-4471 for details")
	if !strings.Contains(got, "[REDACTED_TICKET]") {
		t.Fatalf("Apply(...) = %q, want the newly configured pattern live without a restart", got)
	}
	// The replaced set must be gone rather than merged with the new one, or an
	// operator narrowing their patterns would still be running the old ones.
	if out := p.currentRedaction().Apply("yoshi@urlxl.com"); strings.Contains(out, "[REDACTED_EMAIL]") {
		t.Fatalf("Apply(...) = %q, want the replaced pattern set dropped, not merged", out)
	}
}

// A config update that leaves the patterns alone must not disturb the engine,
// and must still commit the rest of the config.
func TestUpdateConfigWithUnchangedPatternsKeepsRedactionWorking(t *testing.T) {
	p := newRedactionPoller(t)

	next := config.Default()
	next.Timezone = "Etc/UTC"

	p.UpdateConfig(next)

	if got := p.currentConfig().Timezone; got != "Etc/UTC" {
		t.Fatalf("Timezone = %q, want the update committed when the patterns did not change", got)
	}
	if got := p.currentRedaction().Apply("contact me at yoshi@urlxl.com"); !strings.Contains(got, "[REDACTED_EMAIL]") {
		t.Fatalf("redaction stopped working after an unrelated config update: Apply(...) = %q", got)
	}
}
