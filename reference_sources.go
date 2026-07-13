package rbac

import (
	"context"
	"fmt"
	"hash/fnv"
	"os"
)

// ---- Trivial reference sources (source-agnostic loader, Story 2) ---------------
//
// The dumbest possible Source implementations, kept PERMANENTLY as reference sources and as
// the worked example authors of real sources copy from. They exercise the full pipeline
// (fetch -> parse -> snapshot -> engine) without betting on any real transport. A real source
// (HTTP, git, blob storage) is a new implementation of Source and nothing else — these prove
// the seam is real, not fitted to one implementation.

// contentVersion derives a cheap, correct version token from the policy bytes: identical
// content yields an identical version, any change yields a different one. It is a
// non-cryptographic hash — the version is an equality token for change detection, not a
// signature (integrity/authenticity is a separate, deferred concern; see Story 4).
func contentVersion(policy []byte) string {
	h := fnv.New64a()
	_, _ = h.Write(policy)
	return fmt.Sprintf("%016x", h.Sum64())
}

// MemorySource serves a fixed in-memory policy document, versioned by its content hash. It is
// immutable once constructed — useful as an embedded default and as a test fixture.
type MemorySource struct {
	policy  []byte
	version string
}

// NewMemorySource builds a MemorySource over policy, computing its content version once.
func NewMemorySource(policy []byte) MemorySource {
	return MemorySource{policy: policy, version: contentVersion(policy)}
}

// Fetch returns the in-memory bundle. It never fails and ignores the context. For this
// trivial source the raw artifact IS the policy (no envelope), so Raw carries the policy bytes.
func (m MemorySource) Fetch(context.Context) (Bundle, error) {
	return Bundle{Raw: m.policy, Version: m.version}, nil
}

// FileSource serves the policy document at a path, re-read on each fetch and versioned by a
// content hash — so an unchanged file yields an unchanged version, and rewriting the file
// yields a new one. A missing/unreadable file is an ordinary fetch error (the loader treats
// it as a refresh failure and keeps serving last known-good; see Story 3).
type FileSource struct {
	path string
}

// NewFileSource builds a FileSource for path. The file is read on each Fetch, not now.
func NewFileSource(path string) FileSource { return FileSource{path: path} }

// Fetch reads the file (size-gated) and returns it as a content-versioned bundle, or an
// error. The read is capped at maxBundleBytes: an oversized file is rejected after ~that many
// bytes, never read whole, and never hashed — the size-gate runs BEFORE contentVersion.
func (f FileSource) Fetch(context.Context) (Bundle, error) {
	file, err := os.Open(f.path)
	if err != nil {
		return Bundle{}, fmt.Errorf("open policy file %q: %w", f.path, err)
	}
	defer file.Close()

	raw, err := readCapped(file, maxBundleBytes)
	if err != nil {
		return Bundle{}, fmt.Errorf("read policy file %q: %w", f.path, err)
	}
	return Bundle{Raw: raw, Version: contentVersion(raw)}, nil
}
