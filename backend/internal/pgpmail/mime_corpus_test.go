package pgpmail

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// The Go half of the shared MIME corpus. The TypeScript half is
// frontend/src/lib/mimeContent.test.ts, and both read the SAME file.
//
// Two independent MIME parsers exist because the server never sees a
// client-protected account's plaintext. They must agree on which part is the
// display body: buildPGPDeliveries encrypts one plaintext to every To/CC key in
// a single call, so recipients on different custody modes get identical
// ciphertext under ONE signature. When the parsers disagree, that one signature
// authenticates two different messages — which is the property the "signature
// verified" badge exists to deny. Audit run-10 found two such disagreements.
//
// If this test and its TypeScript counterpart ever report different bodies for
// the same case, that is a wire-level trust bug, not a test discrepancy.

type mimeCorpusCase struct {
	Name       string `json:"name"`
	Why        string `json:"why"`
	MIME       string `json:"mime"`
	ExpectBody string `json:"expectBody"`
	ExpectMode string `json:"expectMode"`
	// ExpectGoParseError marks a case where the message is malformed enough
	// that Go's multipart.Reader refuses it outright. The TypeScript parser has
	// no error channel and expresses the same refusal as an empty body, so both
	// sides still agree on what the reader is shown: nothing. Agreement on
	// "no body" is as much a wire-level requirement as agreement on a body —
	// it is the difference between one signature authenticating one reading and
	// authenticating two.
	ExpectGoParseError bool `json:"expectGoParseError,omitempty"`
}

type mimeCorpus struct {
	Cases []mimeCorpusCase `json:"cases"`
}

func loadMIMECorpus(t *testing.T) mimeCorpus {
	t.Helper()
	path := filepath.Join("..", "..", "..", "testdata", "mime-corpus.json")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read shared corpus %s: %v", path, err)
	}
	var corpus mimeCorpus
	if err := json.Unmarshal(raw, &corpus); err != nil {
		t.Fatalf("parse shared corpus: %v", err)
	}
	if len(corpus.Cases) == 0 {
		t.Fatal("shared corpus is empty")
	}
	return corpus
}

func TestSharedMIMECorpus(t *testing.T) {
	for _, tc := range loadMIMECorpus(t).Cases {
		t.Run(tc.Name, func(t *testing.T) {
			body, mode, _, err := ParseContent([]byte(tc.MIME))
			if tc.ExpectGoParseError {
				if err == nil {
					t.Fatalf("expected Go to refuse this message, got body %q\n  why: %s", body, tc.Why)
				}
				if body != "" {
					t.Fatalf("a refused message must yield no body, got %q", body)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseContent: %v", err)
			}
			if body != tc.ExpectBody {
				t.Errorf("body mismatch\n  want %q\n  got  %q\n  why: %s", tc.ExpectBody, body, tc.Why)
			}
			if mode != tc.ExpectMode {
				t.Errorf("mode mismatch: want %q, got %q", tc.ExpectMode, mode)
			}
		})
	}
}
