package rbac

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
	verify  Verifier   // integrity step; defaults to PassthroughVerifier (deferred no-op)
	mu      sync.Mutex // serializes Refresh so version-skip is consistent; Decide stays lock-free
}

// LoaderOption configures a Loader at construction.
type LoaderOption func(*Loader)

// WithVerifier injects a real integrity check in place of the deferred pass-through. This is
// the whole drop-in point: choosing a real check later changes NOTHING in the loader core —
// only the Verifier passed here. A nil verifier is ignored (the pass-through default stays).
func WithVerifier(v Verifier) LoaderOption {
	return func(l *Loader) {
		if v != nil {
			l.verify = v
		}
	}
}

// NewLoader builds a Loader over src. Its integrity step defaults to PassthroughVerifier (a
// marked no-op, deferred pending a source choice); pass WithVerifier to supply a real check.
// Until the first successful Refresh it holds no snapshot, so decisions fail closed (deny).
func NewLoader(src Source, combine Strategy, opts ...LoaderOption) *Loader {
	l := &Loader{src: src, combine: combine, holder: NewHolder(nil), verify: PassthroughVerifier}
	for _, o := range opts {
		o(l)
	}
	return l
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
	// Size-gate FIRST, before verify/extract/parse: reject an oversized artifact so none of
	// that work runs on it. Defense-in-depth — the reference FileSource already bounds its own
	// read, but the seam's whole point is swappable sources, and a future HTTP/blob source may
	// materialize Raw before we ever see it. (Its own hash still ran in Fetch; this gate stops
	// everything downstream.)
	if len(b.Raw) > maxBundleBytes {
		return fmt.Errorf("refresh: bundle is %d bytes, exceeds maximum of %d, serving last known-good", len(b.Raw), maxBundleBytes)
	}
	if cur := l.holder.Current(); cur != nil && cur.ID() == b.Version {
		return nil // unchanged version: parse-once-per-version — no re-verify, no re-parse, no swap
	}
	// New version: run the pipeline in its fixed order — Verify(Raw) → policy bytes → parse →
	// atomic swap. LoadBundle verifies the raw artifact FIRST (producing the policy bytes),
	// then parses under the parser bounds, failing closed (keeping last known-good) on either
	// a rejected bundle or a parse error — a bad refresh never opens access.
	if err := l.holder.LoadBundle(b.Version, b.Raw, l.verify, l.combine); err != nil {
		return fmt.Errorf("refresh: load failed for version %q, serving last known-good: %w", b.Version, err)
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
