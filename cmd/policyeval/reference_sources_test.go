package main

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

// Story 2 (trivial reference source): the reference Sources drive the FULL pipeline
// end-to-end (fetch -> parse -> snapshot -> engine serves it), and a second, structurally
// different Source drives the SAME pipeline unchanged.

// runPipeline is the Story-2 end-to-end composition using existing engine pieces: fetch a
// bundle from any Source, parse it into a version-tagged snapshot, and publish it to a
// holder. It is deliberately Source-blind — the same code below drives both reference
// sources. (Story 3 encapsulates this as Loader.Refresh with the full mechanics.)
func runPipeline(t *testing.T, src Source, h *Holder, combine Strategy) {
	t.Helper()
	b, err := src.Fetch(context.Background())
	if err != nil {
		t.Fatalf("fetch: %v", err)
	}
	snap, err := NewSnapshot(b.Version, b.Policy, combine)
	if err != nil {
		t.Fatalf("parse/snapshot: %v", err)
	}
	h.Set(snap)
}

func TestReferenceSource_EndToEnd(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.json")
	if err := os.WriteFile(path, policyV2JSON, 0o600); err != nil {
		t.Fatal(err)
	}

	// Two structurally different sources, same content -> the SAME pipeline drives both.
	sources := map[string]Source{
		"memory": NewMemorySource(policyV2JSON),
		"file":   NewFileSource(path),
	}
	writeReq := Query{Grants: []Grant{{"write", "obj1", Allow}}, Need: "write", Scope: "obj1"}

	for name, src := range sources {
		t.Run(name, func(t *testing.T) {
			h := NewHolder(nil)
			runPipeline(t, src, h, denyOverrides) // identical pipeline code for either source

			d := h.Decide(writeReq)
			if !d.Allow {
				t.Errorf("%s: engine should serve v2 policy and ALLOW write", name)
			}
			// The published snapshot is versioned by the source's opaque version token.
			b, _ := src.Fetch(context.Background())
			if d.Snapshot != b.Version {
				t.Errorf("%s: snapshot id %q != source version %q", name, d.Snapshot, b.Version)
			}
		})
	}
}

func TestReferenceSource_VersionTracksContent(t *testing.T) {
	ctx := context.Background()

	// Memory: identical content -> identical version; different content -> different version.
	same1, _ := NewMemorySource(policyV1JSON).Fetch(ctx)
	same2, _ := NewMemorySource(policyV1JSON).Fetch(ctx)
	diff, _ := NewMemorySource(policyV2JSON).Fetch(ctx)
	if same1.Version != same2.Version {
		t.Error("identical content must yield an identical version")
	}
	if same1.Version == diff.Version {
		t.Error("different content must yield a different version")
	}

	// File: rewriting the file changes the version (so a refresh can detect the change).
	path := filepath.Join(t.TempDir(), "p.json")
	if err := os.WriteFile(path, policyV1JSON, 0o600); err != nil {
		t.Fatal(err)
	}
	fs := NewFileSource(path)
	before, _ := fs.Fetch(ctx)
	if err := os.WriteFile(path, policyV2JSON, 0o600); err != nil {
		t.Fatal(err)
	}
	after, _ := fs.Fetch(ctx)
	if before.Version == after.Version {
		t.Error("rewriting the file must change the version")
	}
}

// A missing file is an ordinary fetch error — the loader will treat it as a refresh failure
// and keep serving last known-good (Story 3), never crash.
func TestFileSource_MissingFileErrors(t *testing.T) {
	_, err := NewFileSource(filepath.Join(t.TempDir(), "does-not-exist.json")).Fetch(context.Background())
	if err == nil {
		t.Error("fetching a missing file must return an error")
	}
}
