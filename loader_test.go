package rbac

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

// Story 3 (source-independent loader mechanics): parse-on-refresh (never per-decision),
// parse-once-per-version, atomic swap, and last-known-good on any fetch or parse failure.

// alternatingSource returns policy a, then b, then a, ... each content-versioned. Used to
// drive continuous swaps for the atomicity test.
type alternatingSource struct {
	a, b []byte
	n    int
}

func (s *alternatingSource) Fetch(context.Context) (Bundle, error) {
	s.n++
	p := s.a
	if s.n%2 == 0 {
		p = s.b
	}
	return Bundle{Raw: p, Version: contentVersion(p)}, nil
}

// Parse-once-per-version: an unchanged version is not re-parsed (same snapshot pointer); a
// changed version is (new pointer).
func TestLoaderParseOncePerVersion(t *testing.T) {
	path := filepath.Join(t.TempDir(), "p.json")
	if err := os.WriteFile(path, policyV1JSON, 0o600); err != nil {
		t.Fatal(err)
	}
	l := NewLoader(NewFileSource(path), DenyOverrides)
	ctx := context.Background()

	if err := l.Refresh(ctx); err != nil {
		t.Fatal(err)
	}
	snap1 := l.Current()

	if err := l.Refresh(ctx); err != nil { // same file, same version
		t.Fatal(err)
	}
	if l.Current() != snap1 {
		t.Error("unchanged version must not be re-parsed (snapshot must be the same pointer)")
	}

	if err := os.WriteFile(path, policyV2JSON, 0o600); err != nil { // new content -> new version
		t.Fatal(err)
	}
	if err := l.Refresh(ctx); err != nil {
		t.Fatal(err)
	}
	if l.Current() == snap1 {
		t.Error("a changed version must be re-parsed and swapped (new snapshot)")
	}
}

// Decisions never re-parse or swap: the snapshot pointer is stable across many Decides.
func TestLoaderDecideNeverReparses(t *testing.T) {
	l := NewLoader(NewMemorySource(policyV2JSON), DenyOverrides)
	if err := l.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	snap := l.Current()
	for i := 0; i < 1000; i++ {
		if !l.Decide(writeReq()).Allow {
			t.Fatal("v2 should ALLOW write")
		}
	}
	if l.Current() != snap {
		t.Error("Decide must not change the snapshot (no per-decision parse/swap)")
	}
}

// A fetch failure leaves the last known-good snapshot serving.
func TestLoaderFetchFailureKeepsLastKnownGood(t *testing.T) {
	path := filepath.Join(t.TempDir(), "p.json")
	if err := os.WriteFile(path, policyV2JSON, 0o600); err != nil {
		t.Fatal(err)
	}
	l := NewLoader(NewFileSource(path), DenyOverrides)
	ctx := context.Background()
	if err := l.Refresh(ctx); err != nil {
		t.Fatal(err)
	}
	good := l.Current()

	if err := os.Remove(path); err != nil { // source now unreachable
		t.Fatal(err)
	}
	if err := l.Refresh(ctx); err == nil {
		t.Fatal("a fetch failure must return an error")
	}
	if l.Current() != good {
		t.Error("fetch failure must keep the last known-good snapshot")
	}
	if !l.Decide(writeReq()).Allow {
		t.Error("still serving v2 — write must still ALLOW")
	}
}

// A parse failure (a malformed new version) leaves the last known-good snapshot serving.
func TestLoaderParseFailureKeepsLastKnownGood(t *testing.T) {
	path := filepath.Join(t.TempDir(), "p.json")
	if err := os.WriteFile(path, policyV2JSON, 0o600); err != nil {
		t.Fatal(err)
	}
	l := NewLoader(NewFileSource(path), DenyOverrides)
	ctx := context.Background()
	if err := l.Refresh(ctx); err != nil {
		t.Fatal(err)
	}
	good := l.Current()

	// New content (new version) that fails to parse.
	if err := os.WriteFile(path, []byte(`[{"name":"r","effect":"nope","when":{"lit":"x"}}]`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := l.Refresh(ctx); err == nil {
		t.Fatal("a parse failure must return an error")
	}
	if l.Current() != good {
		t.Error("parse failure must keep the last known-good snapshot")
	}
	if !l.Decide(writeReq()).Allow {
		t.Error("still serving v2 — write must still ALLOW")
	}
}

// With no known-good yet, a first-refresh failure fails closed to deny.
func TestLoaderFirstRefreshFailureFailsClosed(t *testing.T) {
	l := NewLoader(NewFileSource(filepath.Join(t.TempDir(), "missing.json")), DenyOverrides)
	if err := l.Refresh(context.Background()); err == nil {
		t.Fatal("missing source must error")
	}
	if l.Current() != nil {
		t.Error("no snapshot should be installed after a failed first refresh")
	}
	if l.Decide(writeReq()).Allow {
		t.Error("no known-good must fail closed to DENY")
	}
}

// The loader's own size-gate rejects an oversized in-memory Raw (defense-in-depth for a
// source that does not bound its own read), before verify or parse, and it never becomes a
// snapshot.
func TestLoaderRawSizeGateRejectsOversized(t *testing.T) {
	big := bytes.Repeat([]byte("x"), maxBundleBytes+1)
	l := NewLoader(NewMemorySource(big), DenyOverrides)
	if err := l.Refresh(context.Background()); err == nil {
		t.Fatal("the loader size-gate must reject an oversized bundle")
	}
	if l.Current() != nil {
		t.Error("an oversized bundle must not become a snapshot")
	}
}

// Atomic swap under -race: every decision reflects a whole snapshot (v1 denies write, v2
// allows it), never a partial/mixed one, while refreshes swap continuously.
func TestLoaderAtomicSwapUnderRace(t *testing.T) {
	l := NewLoader(&alternatingSource{a: policyV1JSON, b: policyV2JSON}, DenyOverrides)
	if err := l.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	v1 := contentVersion(policyV1JSON)
	v2 := contentVersion(policyV2JSON)
	req := writeReq()

	var wg sync.WaitGroup
	for i := 0; i < 8; i++ { // readers
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 3000; j++ {
				d := l.Decide(req)
				switch d.Snapshot {
				case v1:
					if d.Allow {
						t.Errorf("v1 must DENY write")
					}
				case v2:
					if !d.Allow {
						t.Errorf("v2 must ALLOW write")
					}
				default:
					t.Errorf("decision observed a partial/unknown snapshot %q", d.Snapshot)
				}
			}
		}()
	}
	for i := 0; i < 4; i++ { // refreshers: swap continuously
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 800; j++ {
				_ = l.Refresh(context.Background())
			}
		}()
	}
	wg.Wait()
}
