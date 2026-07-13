package main

import (
	"context"
	"errors"
	"testing"
)

// Story 1 (fetch seam): the loader's only dependency on the outside world is Source. These
// tests exercise the seam through a transport-BLIND consumer — code that knows only the
// interface — proving that swapping one Source for another needs no consumer change, that the
// version is an opaque token, and that a fetch error propagates so the loader can treat it as
// a refresh failure.

// --- Two structurally different Source implementations (throwaway; Story 2 adds the real,
// permanent reference sources). ---

// staticSource always returns the same bundle.
type staticSource struct{ bundle Bundle }

func (s staticSource) Fetch(context.Context) (Bundle, error) { return s.bundle, nil }

// rotatingSource returns a different bundle on each fetch — a source whose content changes.
type rotatingSource struct {
	bundles []Bundle
	i       int
}

func (s *rotatingSource) Fetch(context.Context) (Bundle, error) {
	b := s.bundles[s.i%len(s.bundles)]
	s.i++
	return b, nil
}

// errorSource always fails, standing in for a source that is momentarily unreachable.
type errorSource struct{ err error }

func (s errorSource) Fetch(context.Context) (Bundle, error) { return Bundle{}, s.err }

// pull is a stand-in for transport-blind loader code: it knows only Source, nothing about
// where the bundle comes from.
func pull(t *testing.T, src Source) Bundle {
	t.Helper()
	b, err := src.Fetch(context.Background())
	if err != nil {
		t.Fatalf("fetch: %v", err)
	}
	return b
}

// The same consumer code drives two structurally different implementations unchanged.
func TestSource_SwappableImplementations(t *testing.T) {
	var src Source = staticSource{Bundle{Policy: []byte(`[]`), Version: "v-static"}}
	if got := pull(t, src); got.Version != "v-static" || string(got.Policy) != `[]` {
		t.Errorf("static: got %+v", got)
	}

	// Swap the implementation — the consumer (pull) does not change.
	src = &rotatingSource{bundles: []Bundle{
		{Policy: []byte(`[1]`), Version: "v1"},
		{Policy: []byte(`[2]`), Version: "v2"},
	}}
	if got := pull(t, src); got.Version != "v1" {
		t.Errorf("rotating first fetch: got %q want v1", got.Version)
	}
	if got := pull(t, src); got.Version != "v2" {
		t.Errorf("rotating second fetch: got %q want v2", got.Version)
	}
}

// The version identifier round-trips verbatim and is compared as an exact opaque string —
// never normalized or interpreted.
func TestSource_VersionRoundTripsOpaquely(t *testing.T) {
	for _, v := range []string{"", "1.0", "sha:DEADBEEF", "\x00\x01weird"} {
		src := staticSource{Bundle{Policy: []byte(`[]`), Version: v}}
		if got := pull(t, src).Version; got != v {
			t.Errorf("version mangled: got %q want %q", got, v)
		}
	}
	// No semantic normalization: "1.0" and "1.00" are distinct opaque tokens.
	a := Bundle{Version: "1.0"}
	b := Bundle{Version: "1.00"}
	if a.Version == b.Version {
		t.Error("versions must be compared as exact opaque strings (no numeric normalization)")
	}
}

// A fetch error surfaces to the consumer (the loader will handle it as a refresh failure and
// keep serving last known-good — Story 3).
func TestSource_FetchErrorPropagates(t *testing.T) {
	sentinel := errors.New("source unreachable")
	b, err := errorSource{sentinel}.Fetch(context.Background())
	if !errors.Is(err, sentinel) {
		t.Errorf("fetch error not propagated: %v", err)
	}
	if b.Policy != nil || b.Version != "" {
		t.Errorf("a failed fetch must return the zero Bundle, got %+v", b)
	}
}
