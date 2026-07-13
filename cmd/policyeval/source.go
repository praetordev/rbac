package main

import "context"

// ---- The fetch seam (source-agnostic loader, Story 1) --------------------------
//
// The engine consumes immutable snapshots and does not care where they come from. The
// loader should likewise consume RAW POLICY BUNDLES and not care where THOSE come from.
// Source is that boundary: the loader's single dependency on the outside world. Everything
// transport-specific — HTTP, git, blob storage, a local file, a control plane — lives behind
// this interface and NOWHERE else, so choosing the real source later is a drop-in, not a
// rewrite. (The real source is deliberately not chosen here; see the epic non-goals.)

// Bundle is a raw policy document as delivered by a Source, tagged with an opaque version
// identifier. Its bytes are UNPARSED — a Bundle is what arrives before it is parsed into a
// Snapshot.
type Bundle struct {
	// Policy is the raw, unparsed policy document — the same bytes parsePolicy consumes.
	Policy []byte

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
