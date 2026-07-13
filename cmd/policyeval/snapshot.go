package main

import (
	_ "embed"
	"fmt"
	"sync/atomic"
)

// Two policies parsed ONCE, up front, into immutable snapshots. v1 permits only read;
// v2 adds a rule permitting write. Same request -> different decision.
//
//go:embed policy-v1.json
var policyV1JSON []byte

//go:embed policy-v2.json
var policyV2JSON []byte

// Snapshot is the frozen, already-parsed output of the parser: an id, the parsed rules
// (condition trees) and the combining strategy. It is IMMUTABLE — "updating" a policy
// means building a NEW snapshot with NewSnapshot, never editing one in place. All fields
// are unexported and there are no setters, so once built a snapshot cannot change. The
// engine holds a snapshot and never re-parses text on the decision path.
type Snapshot struct {
	id      string
	rules   []Rule
	combine Strategy
}

// NewSnapshot parses policyJSON exactly once and freezes the result. This is the ONLY
// place parsing happens; the decision path (Decide) never parses.
func NewSnapshot(id string, policyJSON []byte, combine Strategy) (*Snapshot, error) {
	rules, err := parsePolicy(policyJSON)
	if err != nil {
		return nil, fmt.Errorf("snapshot %q: %w", id, err)
	}
	// rules is freshly allocated by parsePolicy and never handed out or mutated, so the
	// snapshot owns it exclusively — immutable in practice.
	return &Snapshot{id: id, rules: rules, combine: combine}, nil
}

// ID returns the snapshot's version id.
func (s *Snapshot) ID() string { return s.id }

// Holder is a trivial, atomically-swappable stand-in for the real loader: it just holds
// the current snapshot pointer. Current() returns it; Set installs a new one. The swap is
// a single atomic pointer store, so a reader that has already captured a snapshot keeps
// using it as a new one swaps in — and because snapshots are immutable, nothing it sees
// can change underneath it. (Real file/network fetching is out of scope here.)
type Holder struct {
	cur atomic.Pointer[Snapshot]
}

// NewHolder returns a Holder initialised with s (which may be nil).
func NewHolder(s *Snapshot) *Holder {
	h := &Holder{}
	h.cur.Store(s)
	return h
}

// Current returns the currently-installed snapshot, or nil if none is installed.
func (h *Holder) Current() *Snapshot { return h.cur.Load() }

// Set atomically installs snap as the current snapshot (the "update" — a new value, never
// an in-place edit).
func (h *Holder) Set(snap *Snapshot) { h.cur.Store(snap) }

// Decide captures the current snapshot and evaluates q against it. A decision started this
// way is pinned to the snapshot it captured, even if Set swaps a new one in immediately
// after.
func (h *Holder) Decide(q Query) Decision { return Decide(h.Current(), q) }

// Decide is the decision path: evaluate q against an already-captured, immutable snapshot.
// It NEVER parses. A nil snapshot fails closed (deny) — never crashes, never opens. It
// stamps the deciding snapshot id onto the decision (version pinning); the id is a
// structured field of the decision, surfaced by the trace renderer (Decision.Explain).
func Decide(snap *Snapshot, q Query) Decision {
	if snap == nil {
		return Decision{
			Allow:  false,
			Reason: "no policy snapshot (fail closed)",
			// no snapshot => empty Snapshot id, no rule trace; Explain renders the fail-closed deny.
		}
	}
	d := evaluate(snap.rules, q, snap.combine)
	d.Snapshot = snap.id
	return d
}

// demoSnapshots prints the loader/snapshot/versioning behaviour so `go run` shows it:
// same request, decided under v1, then under v2 after an atomic swap, then fail-closed.
func demoSnapshots() {
	v1 := mustSnapshot(NewSnapshot("v1", policyV1JSON, denyOverrides))
	v2 := mustSnapshot(NewSnapshot("v2", policyV2JSON, denyOverrides))
	h := NewHolder(v1)
	req := Query{Grants: []Grant{{"write", "obj1", Allow}}, Need: "write", Scope: "obj1"}

	fmt.Println("════════ snapshot / versioning demo ════════")
	fmt.Printf("request: %s\n\n", describe(req))

	fmt.Println("holder currently serves v1 (read-only):")
	printResult("v1", h.Decide(req))

	fmt.Print("\n── update: atomic swap v1 → v2 (adds allow-write) ──\n\n")
	h.Set(v2)

	fmt.Println("holder now serves v2 — same request:")
	printResult("v2", h.Decide(req))

	fmt.Println("\nfail-closed — no snapshot installed:")
	var empty Holder
	printResult("none", empty.Decide(req))
}

func mustSnapshot(s *Snapshot, err error) *Snapshot {
	if err != nil {
		panic(err)
	}
	return s
}
