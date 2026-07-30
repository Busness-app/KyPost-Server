package imap

import (
	"testing"

	goimap "github.com/BrianLeishman/go-imap"
)

// TestClientBodyReportsWhichPartItTook covers the value the whole bodyMode wire
// field carries: which MIME part the body actually came from, so no client has
// to guess by inspecting the bytes.
func TestClientBodyReportsWhichPartItTook(t *testing.T) {
	tests := []struct {
		name     string
		email    goimap.Email
		wantBody string
		wantMode string
	}{
		{
			name:     "html part wins when present",
			email:    goimap.Email{HTML: "<p>hi</p>", Text: "hi"},
			wantBody: "<p>hi</p>",
			wantMode: BodyModeHTML,
		},
		{
			name:     "text part when there is no html",
			email:    goimap.Email{Text: "Contact <admin@example.com> today"},
			wantBody: "Contact <admin@example.com> today",
			wantMode: BodyModePlain,
		},
		{
			name:     "whitespace-only html falls through to text",
			email:    goimap.Email{HTML: "   \r\n  ", Text: "real body"},
			wantBody: "real body",
			wantMode: BodyModePlain,
		},
		{
			// The fix. An empty body has no mode to report, and "" is the wire
			// contract's "the server does not know". Reporting "plain" stamped a
			// confident answer on a body that was never parsed — a PGP envelope
			// or an attachment-only message — mailcache.Store.Sync then preserved
			// it across every later update, and the client trusted it over the
			// fallback it would otherwise have applied.
			name:     "no readable part reports no mode at all",
			email:    goimap.Email{},
			wantBody: "",
			wantMode: "",
		},
		{
			name:     "whitespace-only everywhere still reports no mode",
			email:    goimap.Email{HTML: "  ", Text: "\r\n\t "},
			wantBody: "",
			wantMode: "",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			email := tc.email
			body, mode := clientBody(&email)
			if body != tc.wantBody {
				t.Errorf("body = %q, want %q", body, tc.wantBody)
			}
			if mode != tc.wantMode {
				t.Errorf("mode = %q, want %q", mode, tc.wantMode)
			}
		})
	}
}

// TestClientBodyNeverReportsAModeWithoutABody is the invariant stated directly,
// so a future refactor cannot reintroduce the confident-empty combination
// without failing here.
func TestClientBodyNeverReportsAModeWithoutABody(t *testing.T) {
	for _, e := range []goimap.Email{
		{},
		{HTML: ""},
		{Text: ""},
		{HTML: " ", Text: " "},
	} {
		email := e
		body, mode := clientBody(&email)
		if body == "" && mode != "" {
			t.Errorf("clientBody(%+v) reported mode %q for an empty body; empty means unknown", e, mode)
		}
	}
}
