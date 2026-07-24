package pgpautocrypt

import (
	"bytes"
	"testing"
)

func TestParseValid(t *testing.T) {
	// keydata "hello" base64 = aGVsbG8= ; the parser does not parse the key,
	// it only returns the decoded bytes.
	addr, keydata, err := ParseAutocryptHeader("addr=alice@example.com; prefer-encrypt=mutual; keydata=aGVsbG8=")
	if err != nil {
		t.Fatalf("ParseAutocryptHeader: %v", err)
	}
	if addr != "alice@example.com" {
		t.Fatalf("addr = %q, want alice@example.com", addr)
	}
	if !bytes.Equal(keydata, []byte("hello")) {
		t.Fatalf("keydata = %q, want hello", keydata)
	}
}

func TestParseFoldedKeydataStripsWhitespace(t *testing.T) {
	// keydata may arrive with folding whitespace inside the base64.
	_, keydata, err := ParseAutocryptHeader("addr=a@b.com; keydata=aGVs\r\n bG8=")
	if err != nil {
		t.Fatalf("ParseAutocryptHeader: %v", err)
	}
	if !bytes.Equal(keydata, []byte("hello")) {
		t.Fatalf("keydata = %q, want hello", keydata)
	}
}

func TestParseUnderscoreAttributeIgnored(t *testing.T) {
	if _, _, err := ParseAutocryptHeader("addr=a@b.com; _futurehint=x; keydata=aGVsbG8="); err != nil {
		t.Fatalf("non-critical _attribute should be ignored, got %v", err)
	}
}

func TestParseUnknownCriticalAttributeFails(t *testing.T) {
	if _, _, err := ParseAutocryptHeader("addr=a@b.com; danger=1; keydata=aGVsbG8="); err == nil {
		t.Fatalf("expected error for unknown critical attribute")
	}
}

func TestParseMissingKeydata(t *testing.T) {
	if _, _, err := ParseAutocryptHeader("addr=a@b.com"); err == nil {
		t.Fatalf("expected error for missing keydata")
	}
}

func TestParseMissingAddr(t *testing.T) {
	if _, _, err := ParseAutocryptHeader("keydata=aGVsbG8="); err == nil {
		t.Fatalf("expected error for missing addr")
	}
}

func TestParseBadBase64(t *testing.T) {
	if _, _, err := ParseAutocryptHeader("addr=a@b.com; keydata=not!!base64"); err == nil {
		t.Fatalf("expected error for undecodable base64")
	}
}
