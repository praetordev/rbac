package main

import (
	"context"
	"fmt"
	"io"
)

// ---- The fetch seam (source-agnostic loader, Story 1) --------------------------
//
// The engine consumes immutable snapshots and does not care where they come from. The
// loader should likewise consume RAW POLICY BUNDLES and not care where THOSE come from.
// Source is that boundary: the loader's single dependency on the outside world. Everything
// transport-specific — HTTP, git, blob storage, a local file, a control plane — lives behind
// this interface and NOWHERE else, so choosing the real source later is a drop-in, not a
// rewrite. (The real source is deliberately not chosen here; see the epic non-goals.)

// Bundle is what a Source delivers: the raw fetched artifact plus an opaque version. Its
// bytes are UNVERIFIED and UNPARSED — a Bundle is what arrives before the integrity step and
// the parser have run.
type Bundle struct {
	// Raw is the raw fetched artifact — exactly what the Source produced, and exactly what a
	// Verifier consumes. For the trivial reference sources it happens to be the policy bytes
	// themselves; for a future signed source it would be a signed ENVELOPE (signature +
	// payload), with the policy being what verification extracts from it. It is deliberately
	// NOT named "policy": the policy is the OUTPUT of verification, not the raw input. The
	// pipeline order is fixed: Fetch → Verify(Raw) → policy bytes → parse → snapshot.
	Raw []byte

	// Version is an opaque marker of this bundle's version: an etag, a commit sha, a content
	// hash — whatever the Source uses. The loader treats it as an OPAQUE token, compared only
	// for equality (to detect "unchanged since the last fetch"). The loader never interprets,
	// orders, or parses it, exactly as the engine never interprets a capability or scope.
	Version string
}

// Source yields the current raw policy bundle. This is the ONLY method the loader calls, and
// the ONLY place transport lives. A Source implementation knows how to reach policy (a URL, a
// path, a repo); the loader knows only this interface.
//
// Fetch returns the current bundle or an error. A failed Fetch is expected to be ordinary
// (a network blip, the source momentarily down) — the loader treats it as a non-fatal
// refresh failure and keeps serving the last known-good snapshot; it must never be a crash.
// The context carries cancellation/deadline for I/O-bound real sources; trivial sources may
// ignore it.
type Source interface {
	Fetch(ctx context.Context) (Bundle, error)
}

// readCapped reads from r and returns its bytes, but REJECTS (does not truncate) if r holds
// more than limit bytes. It reads at most limit+1 bytes: the one extra byte is enough to
// detect "over the limit" without consuming — or trusting — the rest. This is the size-gate
// sources use so a hostile artifact (a 10 GB file) is refused after ~limit bytes, never read
// whole. Truncating would be worse than the DoS: a giant artifact would silently become a
// valid-but-wrong short one.
func readCapped(r io.Reader, limit int) ([]byte, error) {
	data, err := io.ReadAll(io.LimitReader(r, int64(limit)+1))
	if err != nil {
		return nil, err
	}
	if len(data) > limit {
		return nil, fmt.Errorf("artifact exceeds maximum size of %d bytes", limit)
	}
	return data, nil
}
