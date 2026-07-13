package rbac

import "fmt"

// fleetPolicy is a generic bundle exercising the full condition vocabulary — all / any /
// not / eq / ne / attr / lit — under DenyOverrides. Fixtures are a spaceship fleet; the
// engine interprets none of these strings.
//
//	rule #0 vetoes any operation at the quarantined scope ship-13 (a deny carve-out).
//	rule #1 allows dock-or-scan when the subject holds a matching, non-wildcard,
//	        non-deny grant for the requested scope.
const fleetPolicy = `[
  {
    "name": "deny-quarantined-scope",
    "effect": "deny",
    "when": { "eq": [ { "attr": "scope" }, { "lit": "ship-13" } ] }
  },
  {
    "name": "allow-dock-or-scan",
    "effect": "allow",
    "when": { "all": [
      { "any": [
        { "eq": [ { "attr": "need" }, { "lit": "dock" } ] },
        { "eq": [ { "attr": "need" }, { "lit": "scan" } ] }
      ] },
      { "ne":  [ { "attr": "grant.effect" }, { "lit": "deny" } ] },
      { "not": { "eq": [ { "attr": "grant.cap" }, { "lit": "*" } ] } },
      { "eq":  [ { "attr": "grant.cap" },   { "attr": "need" } ] },
      { "eq":  [ { "attr": "grant.scope" }, { "attr": "scope" } ] }
    ] }
  }
]`

// Example_authoring parses the bundle above and evaluates three requests, showing an
// explicit allow, a deny veto, and a default-deny — and how Decider names the rule (or
// reports that none decided).
func Example_authoring() {
	snap, err := NewSnapshot("fleet-v1", []byte(fleetPolicy), DenyOverrides)
	if err != nil {
		panic(err)
	}
	holds := func(c, s string) []Grant { return []Grant{{Capability: c, Scope: s, Effect: Allow}} }

	asks := []struct {
		label string
		q     Query
	}{
		{"dock ship-9 (held)", Query{Grants: holds("dock", "ship-9"), Need: "dock", Scope: "ship-9"}},
		{"dock ship-13 (quarantined)", Query{Grants: holds("dock", "ship-13"), Need: "dock", Scope: "ship-13"}},
		{"launch ship-9 (no rule)", Query{Grants: holds("launch", "ship-9"), Need: "launch", Scope: "ship-9"}},
	}
	for _, a := range asks {
		d := Decide(snap, a.q)
		if ref, ok := d.Decider(); ok {
			fmt.Printf("%s -> allow=%v (rule #%d %q)\n", a.label, d.Allow, ref.ID, ref.Name)
		} else {
			fmt.Printf("%s -> allow=%v (default-deny)\n", a.label, d.Allow)
		}
	}
	// Output:
	// dock ship-9 (held) -> allow=true (rule #1 "allow-dock-or-scan")
	// dock ship-13 (quarantined) -> allow=false (rule #0 "deny-quarantined-scope")
	// launch ship-9 (no rule) -> allow=false (default-deny)
}

// Example_enforcement wires a Policy Enforcement Point at a resource boundary: it resolves
// the subject's grants from a store the app controls (never from the request), decides, and
// refuses on deny — disclosing only the minimal, structure-free reason to the caller.
func Example_enforcement() {
	snap, err := NewSnapshot("fleet-v1", []byte(fleetPolicy), DenyOverrides)
	if err != nil {
		panic(err)
	}

	// Grants keyed by a VERIFIED identity, from a store only the app writes — NOT from
	// request-controlled input. The provenance obligation is detailed in the trust contract.
	trustedGrants := map[string][]Grant{
		"pilot-42": {{Capability: "dock", Scope: "ship-9", Effect: Allow}},
	}

	// authorize is the PEP: no operation proceeds without a permit. It hands the caller only
	// what is safe to reveal — the minimal reason.
	authorize := func(principal, need, scope string) (proceed bool, tellCaller string) {
		d := Decide(snap, Query{Grants: trustedGrants[principal], Need: need, Scope: scope})
		return d.Allow, d.Disclose(Minimal)
	}

	for _, op := range []struct{ principal, need, scope string }{
		{"pilot-42", "dock", "ship-9"},   // holds the grant      -> permitted
		{"pilot-42", "launch", "ship-9"}, // holds no such grant  -> refused
		{"stowaway", "dock", "ship-9"},   // holds no grants      -> refused
	} {
		proceed, msg := authorize(op.principal, op.need, op.scope)
		if proceed {
			fmt.Printf("%s %s@%s: PROCEED\n", op.principal, op.need, op.scope)
		} else {
			fmt.Printf("%s %s@%s: REFUSED (%q)\n", op.principal, op.need, op.scope, msg)
		}
	}
	// Output:
	// pilot-42 dock@ship-9: PROCEED
	// pilot-42 launch@ship-9: REFUSED ("access denied")
	// stowaway dock@ship-9: REFUSED ("access denied")
}
