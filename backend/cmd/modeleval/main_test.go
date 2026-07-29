package main

import (
	"strings"
	"testing"
)

var stock = []string{"Primary", "Promotions", "Social", "Updates"}

func TestResolveLabelMirrorsProduction(t *testing.T) {
	tests := []struct {
		name string
		raw  string
		want string
	}{
		{"bare label", "Primary", "Primary"},
		{"trailing whitespace", "  Updates \n", "Updates"},
		{"case insensitive", "promotions", "Promotions"},
		{"structured output is JSON-quoted", `"Social"`, "Social"},
		{"label on its own line after preamble", "Sure, here is the label:\nUpdates", "Updates"},
		{"prefixed line falls back to substring match", "Label: Promotions", "Promotions"},
		{"empty-message noise line is dropped", "This message is empty. Sorry about that.\nSocial", "Social"},
		{"no label at all", "I cannot determine a category.", ""},
		{"out-of-allowlist label", "General", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := resolveLabel(tt.raw, stock); got != tt.want {
				t.Fatalf("resolveLabel(%q) = %q, want %q", tt.raw, got, tt.want)
			}
		})
	}
}

// The lenient matcher production falls back to is strings.Contains-based and
// iterates the ALLOWLIST, not the text — so it returns whichever allowlisted
// label appears earliest in the allowlist that occurs anywhere in the output,
// regardless of position or negation. "Primary" sorts first, so any prose
// mentioning it wins even when the model's actual answer was something else.
//
// The harness must reproduce this rather than quietly score it as correct,
// otherwise it would report accuracy production does not actually achieve.
func TestResolveLabelInheritsAllowlistOrderBias(t *testing.T) {
	raw := "This is not Primary, it is Promotions."
	got := resolveLabel(raw, stock)
	if got != "Primary" {
		t.Fatalf("resolveLabel(%q) = %q; production's matcher returns the first allowlist entry present in the text, so %q is expected here", raw, got, "Primary")
	}
}

// SelectLabelFromText special-cases Questionable ahead of every other label.
// Config E puts Questionable in the allowlist, so this precedence is live.
func TestQuestionablePrecedenceUnderExpandedAllowlist(t *testing.T) {
	expanded := append(append([]string{}, stock...), "Important", "Questionable", "Finance", "Travel")
	raw := "Primary, though the sender looks questionable."
	if got := resolveLabel(raw, expanded); got != "Questionable" {
		t.Fatalf("resolveLabel(%q) = %q, want Questionable (hard-coded precedence in classifier.SelectLabelFromText)", raw, got)
	}
}

func TestIsStrictLabel(t *testing.T) {
	strict := []string{"Primary", "  Updates  ", `"Social"`, "promotions"}
	for _, s := range strict {
		if !isStrictLabel(s, stock) {
			t.Errorf("isStrictLabel(%q) = false, want true", s)
		}
	}
	loose := []string{"Label: Primary", "Primary — this is a work email", "", "General"}
	for _, s := range loose {
		if isStrictLabel(s, stock) {
			t.Errorf("isStrictLabel(%q) = true, want false", s)
		}
	}
}

func TestLooksLikeRetryNoise(t *testing.T) {
	noisy := []string{
		"tools",
		"[some-bracketed-preamble]\ntools",
		"This message is empty. Sorry about that.",
		"",
	}
	for _, s := range noisy {
		if !looksLikeRetryNoise(s) {
			t.Errorf("looksLikeRetryNoise(%q) = false, want true", s)
		}
	}
	if looksLikeRetryNoise("Primary") {
		t.Error("looksLikeRetryNoise(\"Primary\") = true, want false")
	}
}

// composeBody must reproduce poller.go:896-909 byte for byte, because the
// reference-decisions block landing inside the untrusted fence is one of the
// things the injection bucket measures.
func TestComposeBodyMirrorsPoller(t *testing.T) {
	fewshot := renderFewshot([]fewshotEntry{{Sender: "a@b.example", Subject: "Hi", Label: "Primary"}})
	got := composeBody("hello", fewshot)
	want := "hello\n---\nRecent labeling decisions for reference:\n- From: a@b.example, Subject: Hi → Label: Primary"
	if got != want {
		t.Fatalf("composeBody() = %q, want %q", got, want)
	}
}

func TestComposeBodyTruncatesAt2000Bytes(t *testing.T) {
	long := strings.Repeat("x", 3000)
	got := composeBody(long, "")
	if len(got) != productionBodyLimit {
		t.Fatalf("composeBody truncated to %d bytes, want %d", len(got), productionBodyLimit)
	}
}

func TestRenderFewshotEmpty(t *testing.T) {
	if got := renderFewshot(nil); got != "" {
		t.Fatalf("renderFewshot(nil) = %q, want empty", got)
	}
}
