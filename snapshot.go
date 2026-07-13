package rbac

import (
	"fmt"
	"sync/atomic"
)

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

// Load parses policyJSON into a new snapshot and installs it ONLY if parsing succeeds. A
// malformed, oversized, or pathological bundle is rejected: the error is returned and the
// current (last known-good) snapshot stays in place untouched. A bad load therefore can
// never open access, clear the policy, or crash the engine — it fails closed to whatever
// was already installed (which may be nil, i.e. deny-all).
func (h *Holder) Load(id string, policyJSON []byte, combine Strategy) error {
	snap, err := NewSnapshot(id, policyJSON, combine)
	if err != nil {
		return err // fail closed: current snapshot untouched
	}
	h.Set(snap)
	return nil
}

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
