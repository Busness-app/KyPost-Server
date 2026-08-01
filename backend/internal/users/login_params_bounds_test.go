package users

import (
	"context"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// The server used to enforce only MinLoginIterations. Anything above it was
// stored verbatim, including values the official client refuses to derive with
// — so a client holding valid credentials could persist a work factor that
// bricked the account it belonged to, and the only interface for fixing it was
// the client that could no longer sign in.

// testLegacyPassword is the plaintext newLegacyTestUser registers, so the
// upgrade path below has a credential it can actually prove.
const testLegacyPassword = "a-sufficiently-long-password"

// newLegacyTestUser returns a store plus a user that still authenticates the
// legacy way — the only kind UpgradeToDerivedAuth acts on.
func newLegacyTestUser(t *testing.T) (*Store, User) {
	t.Helper()
	store := newTestStore(t)
	u, err := store.Create(context.Background(), "legacy-user", testLegacyPassword, RoleUser)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	return store, u
}

func TestSetDerivedAuthRejectsOutOfRangeLoginParameters(t *testing.T) {
	store, bootstrap := newLegacyTestUser(t)
	ctx := context.Background()
	const salt = "YWFhYWFhYWFhYWFhYWFhYQ==" // 16 bytes, as both salt sources produce
	const secret = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

	for _, tc := range []struct {
		name       string
		salt       string
		iterations int
		wantErr    bool
	}{
		{"at the floor", salt, MinLoginIterations, false},
		{"at the ceiling", salt, MaxLoginIterations, false},
		{"below the floor", salt, MinLoginIterations - 1, true},
		{"above the ceiling", salt, MaxLoginIterations + 1, true},
		{"absurdly above the ceiling", salt, 1 << 40, true},
		{"salt is not base64", "not base64!!", MinLoginIterations, true},
		{"salt decodes too short", "c2FsdA==", MinLoginIterations, true},
		{"salt is empty", "", MinLoginIterations, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := store.SetDerivedAuth(ctx, bootstrap.ID, secret, tc.salt, tc.iterations, false)
			if tc.wantErr && err == nil {
				t.Fatalf("SetDerivedAuth(salt=%q, iterations=%d) = nil, want an error", tc.salt, tc.iterations)
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("SetDerivedAuth(salt=%q, iterations=%d) = %v, want nil", tc.salt, tc.iterations, err)
			}
		})
	}
}

func TestUpgradeToDerivedAuthRejectsOutOfRangeLoginParameters(t *testing.T) {
	store, bootstrap := newLegacyTestUser(t)
	ctx := context.Background()
	const salt = "YWFhYWFhYWFhYWFhYWFhYQ=="
	const secret = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

	if err := store.UpgradeToDerivedAuth(ctx, bootstrap.ID, testLegacyPassword, secret, salt, MaxLoginIterations+1); err == nil {
		t.Fatal("UpgradeToDerivedAuth accepted a work factor the client refuses to derive with")
	}
	u, err := store.Get(bootstrap.ID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if u.UsesDerivedAuth() {
		t.Fatal("a rejected upgrade still converted the account")
	}
}

// TestLoginIterationCeilingMatchesFrontend pins the two halves of one contract
// together by reading the other half.
//
// MaxLoginIterations is only meaningful because the browser enforces the same
// number: the server refuses to STORE what the client refuses to USE. Two
// constants in two languages agreeing by convention is exactly the arrangement
// that produced the bug — the server had no ceiling at all — so the agreement
// is asserted rather than commented.
func TestLoginIterationCeilingMatchesFrontend(t *testing.T) {
	path := filepath.Join("..", "..", "..", "frontend", "src", "lib", "authSecret.ts")
	source, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	for constant, want := range map[string]int{
		"MIN_ITERATIONS": MinLoginIterations,
		"MAX_ITERATIONS": MaxLoginIterations,
	} {
		re := regexp.MustCompile(`const ` + constant + ` = ([0-9_]+);`)
		match := re.FindSubmatch(source)
		if match == nil {
			t.Fatalf("%s not found in authSecret.ts; if it was renamed, update this test and keep the two in agreement", constant)
		}
		got, err := strconv.Atoi(strings.ReplaceAll(string(match[1]), "_", ""))
		if err != nil {
			t.Fatalf("parse %s: %v", constant, err)
		}
		if got != want {
			t.Fatalf("authSecret.ts %s = %d, users package = %d; the server would accept a login parameter its own client rejects", constant, got, want)
		}
	}
}
