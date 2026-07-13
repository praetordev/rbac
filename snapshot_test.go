package rbac

import (
	"strings"
	"testing"
)

func mustSnap(t *testing.T, id string, js []byte, combine Strategy) *Snapshot {
	t.Helper()
	s, err := NewSnapshot(id, js, combine)
	if err != nil {
		t.Fatalf("build snapshot %s: %v", id, err)
	}
	return s
}

// writeReq is the request that v1 denies and v2 permits: write on obj1 with a matching
// allow grant. The subject's grants never change — only the policy does.
func writeReq() Query {
	return Query{Grants: []Grant{{"write", "obj1", Allow}}, Need: "write", Scope: "obj1"}
}

// 1. Same request, different snapshots -> different decisions.
func TestDecisionDiffersBySnapshot(t *testing.T) {
	v1 := mustSnap(t, "v1", policyV1JSON, DenyOverrides)
	v2 := mustSnap(t, "v2", policyV2JSON, DenyOverrides)

	if Decide(v1, writeReq()).Allow {
		t.Error("v1 should DENY write")
	}
	if !Decide(v2, writeReq()).Allow {
		t.Error("v2 should ALLOW write")
	}
}

// 2. Atomic swap: flip the holder v1 -> v2; decisions before use v1's rules, after use v2's.
func TestAtomicSwap(t *testing.T) {
	v1 := mustSnap(t, "v1", policyV1JSON, DenyOverrides)
	v2 := mustSnap(t, "v2", policyV2JSON, DenyOverrides)
	h := NewHolder(v1)

	before := h.Decide(writeReq())
	if before.Allow || before.Snapshot != "v1" {
		t.Fatalf("before swap: want DENY under v1, got allow=%v snapshot=%q", before.Allow, before.Snapshot)
	}

	h.Set(v2) // atomic swap

	after := h.Decide(writeReq())
	if !after.Allow || after.Snapshot != "v2" {
		t.Fatalf("after swap: want ALLOW under v2, got allow=%v snapshot=%q", after.Allow, after.Snapshot)
	}
}

// 3. Mid-flight immutability: a decision that captured v1 stays v1 even if v2 swaps in
// before it finishes.
func TestMidFlightImmutability(t *testing.T) {
	v1 := mustSnap(t, "v1", policyV1JSON, DenyOverrides)
	v2 := mustSnap(t, "v2", policyV2JSON, DenyOverrides)
	h := NewHolder(v1)

	snap := h.Current() // capture v1 at the start of a decision
	h.Set(v2)           // v2 swaps in mid-flight
	d := Decide(snap, writeReq())

	if d.Allow || d.Snapshot != "v1" {
		t.Fatalf("captured decision must stay v1 (DENY), got allow=%v snapshot=%q", d.Allow, d.Snapshot)
	}
	if h.Current().ID() != "v2" {
		t.Fatalf("holder should now expose v2, got %q", h.Current().ID())
	}
}

// 4. Version pinning: the decision reports which snapshot produced it — as a field and in
// the trace.
func TestVersionPinning(t *testing.T) {
	v2 := mustSnap(t, "v2", policyV2JSON, DenyOverrides)
	d := Decide(v2, writeReq())

	if d.Snapshot != "v2" {
		t.Errorf("Decision.Snapshot = %q, want v2", d.Snapshot)
	}
	if d.Trace().Snapshot != "v2" {
		t.Errorf("structured Trace.Snapshot = %q, want v2", d.Trace().Snapshot)
	}
	if !strings.Contains(d.Explain(), "v2") {
		t.Errorf("rendered trace does not name snapshot id v2:\n%s", d.Explain())
	}
}

// 5. Fail closed: nil / absent snapshot denies — never opens, never panics.
func TestFailClosed(t *testing.T) {
	d := Decide(nil, writeReq())
	if d.Allow {
		t.Error("nil snapshot must DENY")
	}

	var h Holder // zero value: no snapshot installed
	if h.Current() != nil {
		t.Fatal("zero-value holder should have no snapshot")
	}
	if got := h.Decide(writeReq()); got.Allow {
		t.Error("holder with no snapshot must DENY (fail closed)")
	}
}

// Sanity: both snapshots agree where they should — read is allowed under v1 and v2.
func TestReadAllowedBothVersions(t *testing.T) {
	v1 := mustSnap(t, "v1", policyV1JSON, DenyOverrides)
	v2 := mustSnap(t, "v2", policyV2JSON, DenyOverrides)
	readReq := Query{Grants: []Grant{{"read", "obj1", Allow}}, Need: "read", Scope: "obj1"}

	if !Decide(v1, readReq).Allow {
		t.Error("v1 should ALLOW read")
	}
	if !Decide(v2, readReq).Allow {
		t.Error("v2 should ALLOW read")
	}
}
