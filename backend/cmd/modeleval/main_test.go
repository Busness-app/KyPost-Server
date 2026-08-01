package main

import (
	"bytes"
	"strings"
	"testing"
)

var stock = []string{"Primary", "Promotions", "Social", "Updates"}

func TestResolveLabelMirrorsProduction(t *testing.T) {
	tests := []struct{ name, raw, want string }{
		{"bare label", "Primary", "Primary"}, {"trailing whitespace", "  Updates \n", "Updates"}, {"case insensitive", "promotions", "Promotions"}, {"structured output is JSON-quoted", `"Social"`, "Social"}, {"label on its own line after preamble", "Sure, here is the label:\nUpdates", "Updates"}, {"prefixed line falls back to substring match", "Label: Promotions", "Promotions"}, {"empty-message noise line is dropped", "This message is empty. Sorry about that.\nSocial", "Social"}, {"no label at all", "I cannot determine a category.", ""}, {"out-of-allowlist label", "General", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := resolveLabel(tt.raw, stock); got != tt.want {
				t.Fatalf("resolveLabel(%q) = %q, want %q", tt.raw, got, tt.want)
			}
		})
	}
}

func TestResolveLabelInheritsAllowlistOrderBias(t *testing.T) {
	if got := resolveLabel("This is not Primary, it is Promotions.", stock); got != "Primary" {
		t.Fatalf("got %q, want Primary", got)
	}
}

func TestQuestionablePrecedenceUnderExpandedAllowlist(t *testing.T) {
	expanded := append(append([]string{}, stock...), "Important", "Questionable", "Finance", "Travel")
	if got := resolveLabel("Primary, though the sender looks questionable.", expanded); got != "Questionable" {
		t.Fatalf("got %q, want Questionable", got)
	}
}

func TestIsStrictLabel(t *testing.T) {
	for _, s := range []string{"Primary", "  Updates  ", `"Social"`, "promotions"} {
		if !isStrictLabel(s, stock) {
			t.Errorf("%q is strict", s)
		}
	}
	for _, s := range []string{"Label: Primary", "Primary — this is a work email", "", "General"} {
		if isStrictLabel(s, stock) {
			t.Errorf("%q is loose", s)
		}
	}
}

func TestLooksLikeRetryNoise(t *testing.T) {
	for _, s := range []string{"tools", "[some-bracketed-preamble]\ntools", "This message is empty. Sorry about that.", ""} {
		if !looksLikeRetryNoise(s) {
			t.Errorf("%q not noise", s)
		}
	}
	if looksLikeRetryNoise("Primary") {
		t.Error("Primary is noise")
	}
}

func TestComposeBodyMirrorsPoller(t *testing.T) {
	fewshot := renderFewshot([]fewshotEntry{{Sender: "a@b.example", Subject: "Hi", Label: "Primary"}})
	if got, want := composeBody("hello", fewshot), "hello\n---\nRecent labeling decisions for reference:\n- From: a@b.example, Subject: Hi → Label: Primary"; got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestComposeBodyTruncatesAt2000Bytes(t *testing.T) {
	if got := composeBody(strings.Repeat("x", 3000), ""); len(got) != productionBodyLimit {
		t.Fatalf("got %d, want %d", len(got), productionBodyLimit)
	}
}

func TestRenderFewshotEmpty(t *testing.T) {
	if got := renderFewshot(nil); got != "" {
		t.Fatalf("got %q", got)
	}
}

func TestReadOllamaResponseRejectsOversizeBody(t *testing.T) {
	if _, err := readOllamaResponse(bytes.NewReader(make([]byte, maxOllamaResponseBytes+1))); err == nil {
		t.Fatal("oversize Ollama response was accepted")
	}
}
