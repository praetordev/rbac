package main

import (
	"context"
	"fmt"
	"sync"
)

// ---- Source-independent loader mechanics (Story 3) -----------------------------
//
// Loader is the orchestration between "some bytes arrived from a Source" and "the engine is
// serving a new immutable snapshot." It is entirely source-independent: it depends only on
// the Source seam and the existing snapshot machinery, so choosing the real source later
// changes nothing here.
//
// Guarantees:
//   - Parse-on-refresh, never on the decision path. Parsing happens once per version, inside
//     Refresh; Decide only reads an already-parsed snapshot.
//   - Parse-once-per-version. If the fetched version equals the one currently serving, the
//     refresh is a cheap no-op: no re-fetch-parse, no swap.
//   - Atomic swap. Installation is the Holder's single atomic pointer store, so no in-flight
//     decision ever observes a partial or mixed policy.
//   - Last-known-good on ANY failure. A fetch error or a parse error leaves the previous good
//     snapshot serving; a bad refresh never opens access, never clears policy, never crashes.
type Loader struct {
	src     Source
	combine Strategy
	holder  *Holder
	mu      sync.Mutex // serializes Refresh so version-skip is consistent; Decide stays lock-free
}

// NewLoader builds a Loader over src. Until the first successful Refresh it holds no snapshot,
// so decisions fail closed (deny).
func NewLoader(src Source, combine Strategy) *Loader {
	return &Loader{src: src, combine: combine, holder: NewHolder(nil)}
}

// Refresh fetches the current bundle and, if it is a new version, parses it and atomically
// publishes it as the current snapshot. Any failure — fetch or parse — returns an error and
// leaves the last known-good snapshot serving.
func (l *Loader) Refresh(ctx context.Context) error {
	l.mu.Lock()
	defer l.mu.Unlock()

	b, err := l.src.Fetch(ctx)
	if err != nil {
		return fmt.Errorf("refresh: fetch failed, serving last known-good: %w", err)
	}
	if cur := l.holder.Current(); cur != nil && cur.ID() == b.Version {
		return nil // unchanged version: parse-once-per-version — no re-parse, no swap
	}
	// New version: Holder.Load parses under the parser bounds and swaps atomically, itself
	// failing closed (keeping last known-good) on a parse error.
	if err := l.holder.Load(b.Version, b.Policy, l.combine); err != nil {
		return fmt.Errorf("refresh: parse failed for version %q, serving last known-good: %w", b.Version, err)
	}
	return nil
}

// Decide serves the current snapshot. It never parses; with no snapshot loaded it fails
// closed (deny).
func (l *Loader) Decide(q Query) Decision { return l.holder.Decide(q) }

// Current returns the currently-serving snapshot, or nil if none has loaded.
func (l *Loader) Current() *Snapshot { return l.holder.Current() }

// Version returns the currently-serving version, or "" if none has loaded.
func (l *Loader) Version() string {
	if s := l.holder.Current(); s != nil {
		return s.ID()
	}
	return ""
}

func verdictWord(d Decision) string {
	if d.Allow {
		return "ALLOW"
	}
	return "DENY"
}

// demoLoader prints the loader serving a policy fetched from a Source, and failing closed
// when the source is unreachable.
func demoLoader() {
	ctx := context.Background()
	req := Query{Grants: []Grant{{"write", "obj1", Allow}}, Need: "write", Scope: "obj1"}

	fmt.Println("\n════════ source-agnostic loader demo ════════")

	l := NewLoader(NewMemorySource(policyV2JSON), denyOverrides)
	_ = l.Refresh(ctx)
	fmt.Printf("fetched + parsed version %s from a Source; write @ obj1 -> %s\n", l.Version(), verdictWord(l.Decide(req)))

	bad := NewLoader(NewFileSource("/nonexistent/policy.json"), denyOverrides)
	err := bad.Refresh(ctx)
	fmt.Printf("\nunreachable source -> refresh error: %v\n", err)
	fmt.Printf("  serving version %q; write @ obj1 -> %s (fail closed, last known-good)\n", bad.Version(), verdictWord(bad.Decide(req)))
}
