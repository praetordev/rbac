package rbac

import "fmt"

// ExampleDecide is the smallest correct call end to end: parse a policy into an immutable
// snapshot, resolve the subject's grants, build a Query, evaluate it, and read both the
// verdict and the rule that decided it.
//
// The fixtures are deliberately GENERIC — a spaceship fleet. The engine interprets none of
// these strings; "launch" and "ship-9" are opaque tokens, exactly as your own capability and
// scope names would be.
func ExampleDecide() {
	// A generic policy in the canonical JSON condition-tree form: allow any Need at any Scope
	// for which the subject holds a matching, allowing grant (grant.cap == need and
	// grant.scope == scope and grant.effect == "allow").
	policy := []byte(`[
		{"name":"allow-matching-grant","effect":"allow","when":{"all":[
			{"eq":[{"attr":"grant.effect"},{"lit":"allow"}]},
			{"eq":[{"attr":"grant.cap"},{"attr":"need"}]},
			{"eq":[{"attr":"grant.scope"},{"attr":"scope"}]}
		]}}
	]`)
	snap, err := NewSnapshot("fleet-v1", policy, DenyOverrides)
	if err != nil {
		panic(err)
	}

	// Grants resolved from a trusted store keyed by a verified identity — NOT from the
	// request. The subject may pilot ship-9.
	q := Query{
		Grants: []Grant{{Capability: "launch", Scope: "ship-9", Effect: Allow}},
		Need:   "launch",
		Scope:  "ship-9",
	}
	d := Decide(snap, q)
	fmt.Println("launch ship-9 ->", d.Allow)
	if ref, ok := d.Decider(); ok {
		fmt.Printf("  decided by rule #%d %q (%s)\n", ref.ID, ref.Name, ref.Effect)
	}

	// A request the subject holds no matching grant for (wrong scope): default-deny, and no
	// rule decides — Decider reports ok == false.
	q2 := Query{
		Grants: []Grant{{Capability: "launch", Scope: "ship-9", Effect: Allow}},
		Need:   "launch",
		Scope:  "ship-42",
	}
	d2 := Decide(snap, q2)
	fmt.Println("launch ship-42 ->", d2.Allow)
	if _, ok := d2.Decider(); !ok {
		fmt.Println("  default-deny (no rule matched)")
	}

	// Output:
	// launch ship-9 -> true
	//   decided by rule #0 "allow-matching-grant" (ALLOW)
	// launch ship-42 -> false
	//   default-deny (no rule matched)
}
