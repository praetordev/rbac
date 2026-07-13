package main

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// Story 4 (integrity as a marked, deferred step): the refresh pipeline runs an integrity
// step (the Verifier seam) between fetch and parse. The default is a documented pass-through;
// a real check drops in via WithVerifier with no loader change; a rejected bundle is treated
// like any other refresh failure (last-known-good preserved, access never opened).

// The default integrity step accepts, so the pipeline runs end to end.
func TestLoaderDefaultIntegrityIsPassthrough(t *testing.T) {
	if got, err := PassthroughVerifier([]byte("anything")); err != nil || string(got) != "anything" {
		t.Fatalf("PassthroughVerifier must return the bundle unchanged, got %q err=%v", got, err)
	}

	l := NewLoader(NewMemorySource(policyV2JSON), denyOverrides) // default = pass-through
	if err := l.Refresh(context.Background()); err != nil {
		t.Fatalf("default pass-through must accept and load: %v", err)
	}
	if !l.Decide(writeReq()).Allow {
		t.Error("engine should serve the loaded v2 policy (write ALLOW)")
	}
}

// A rejected bundle is treated exactly like any other refresh failure: the last known-good
// snapshot keeps serving and access never opens.
func TestLoaderRejectedBundleKeepsLastKnownGood(t *testing.T) {
	// A stand-in real check: accept v1, reject v2 (as if v2 were unsigned/tampered).
	verify := func(bundle []byte) ([]byte, error) {
		if bytes.Equal(bundle, policyV2JSON) {
			return nil, errors.New("untrusted bundle")
		}
		return bundle, nil
	}

	path := filepath.Join(t.TempDir(), "p.json")
	if err := os.WriteFile(path, policyV1JSON, 0o600); err != nil {
		t.Fatal(err)
	}
	l := NewLoader(NewFileSource(path), denyOverrides, WithVerifier(verify))
	ctx := context.Background()

	if err := l.Refresh(ctx); err != nil {
		t.Fatalf("v1 should pass the integrity check: %v", err)
	}
	good := l.Current()

	if err := os.WriteFile(path, policyV2JSON, 0o600); err != nil { // new version, will be rejected
		t.Fatal(err)
	}
	if err := l.Refresh(ctx); err == nil {
		t.Fatal("a rejected bundle must return an error")
	}
	if l.Current() != good {
		t.Error("a rejected bundle must keep the last known-good snapshot")
	}
	// v1 allows read but not write; confirm it is still v1 serving (no accidental open).
	readReq := Query{Grants: []Grant{{"read", "obj1", Allow}}, Need: "read", Scope: "obj1"}
	if !l.Decide(readReq).Allow || l.Decide(writeReq()).Allow {
		t.Error("still serving v1: read ALLOW, write DENY")
	}
}

// With no known-good yet, a rejected first refresh fails closed to deny.
func TestLoaderRejectedFirstRefreshFailsClosed(t *testing.T) {
	rejectAll := func([]byte) ([]byte, error) { return nil, errors.New("untrusted") }
	l := NewLoader(NewMemorySource(policyV2JSON), denyOverrides, WithVerifier(rejectAll))

	if err := l.Refresh(context.Background()); err == nil {
		t.Fatal("a rejected first refresh must error")
	}
	if l.Current() != nil {
		t.Error("no snapshot should be installed")
	}
	if l.Decide(writeReq()).Allow {
		t.Error("no known-good must fail closed to DENY")
	}
}

// The integrity step runs once per NEW version (and is skipped, along with parse, for an
// unchanged version — the already-verified bundle is not re-checked).
func TestLoaderIntegrityRunsPerNewVersion(t *testing.T) {
	calls := 0
	verify := func(bundle []byte) ([]byte, error) {
		calls++
		return bundle, nil
	}

	path := filepath.Join(t.TempDir(), "p.json")
	if err := os.WriteFile(path, policyV1JSON, 0o600); err != nil {
		t.Fatal(err)
	}
	l := NewLoader(NewFileSource(path), denyOverrides, WithVerifier(verify))
	ctx := context.Background()

	if err := l.Refresh(ctx); err != nil { // new version -> verify
		t.Fatal(err)
	}
	if err := l.Refresh(ctx); err != nil { // unchanged version -> skip (no verify)
		t.Fatal(err)
	}
	if calls != 1 {
		t.Errorf("integrity check ran %d times, want 1 (once per new version, skipped when unchanged)", calls)
	}

	if err := os.WriteFile(path, policyV2JSON, 0o600); err != nil { // new version -> verify again
		t.Fatal(err)
	}
	if err := l.Refresh(ctx); err != nil {
		t.Fatal(err)
	}
	if calls != 2 {
		t.Errorf("integrity check ran %d times, want 2 after a version change", calls)
	}
}
