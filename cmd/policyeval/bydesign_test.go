package main

import (
	"encoding/json"
	"testing"
)

// Story 2 (prove-by-design): for threats the engine closes BY DESIGN, the deliverable is a
// passing test plus a written finding (see epic-rbac/TRUST-BOUNDARY.md) that says the engine
// is correct here and the perimeter is elsewhere. NO engine code is added by this file — it
// only exercises the existing evaluator to demonstrate faithful evaluation of bad inputs.
//
// "Faithful evaluation" is the whole point: the engine does exactly what the policy and the
// supplied attributes say, interpreting nothing. That is why it is safe from injection and
// why over-broad policies / forged attributes are perimeter problems, not engine bugs.

func mustPolicy(t *testing.T, js string) []Rule {
	t.Helper()
	rules, err := parsePolicy([]byte(js))
	if err != nil {
		t.Fatalf("policy must parse: %v\npolicy: %s", err, js)
	}
	return rules
}

// exactAllowPolicy permits when the subject holds an allow grant whose capability equals the
// requested need at the requested scope. Used to show the engine acts purely on the grants
// it is handed, with no notion of their provenance.
const exactAllowPolicy = `[{"name":"exact-allow","effect":"allow","when":{"all":[
	{"eq":[{"attr":"grant.effect"},{"lit":"allow"}]},
	{"eq":[{"attr":"grant.cap"},{"attr":"need"}]},
	{"eq":[{"attr":"grant.scope"},{"attr":"scope"}]}
]}}]`

// Threat 7 — an over-broad "permit-always" policy is evaluated FAITHFULLY. The engine does
// not refuse it or second-guess its breadth; it permits exactly what the policy says. The
// defense is the policy SOURCE (Story 4), never the evaluator.
func TestByDesign_PermitAlwaysPolicyEvaluatedFaithfully(t *testing.T) {
	// One rule whose condition is a tautology: it matches any grant the subject holds, so it
	// permits every request from anyone holding even one grant.
	rules := mustPolicy(t, `[{"name":"permit-anything","effect":"allow","when":{"eq":[{"lit":"1"},{"lit":"1"}]}}]`)

	for _, need := range []string{"read", "write", "delete", "anything-at-all"} {
		q := Query{Grants: []Grant{{"some-token", "", Allow}}, Need: need, Scope: "any-scope"}
		d := evaluate(rules, q, denyOverrides)
		if !d.Allow {
			t.Errorf("over-broad policy must faithfully permit %q, got deny", need)
		}
		if ref, ok := d.Decider(); !ok || ref.Name != "permit-anything" {
			t.Errorf("expected permit-anything to decide %q, got %+v (ok=%v)", need, ref, ok)
		}
	}
}

// Threat 8 — the engine cannot distinguish a FORGED grant from a legitimately-issued one. It
// evaluates whatever the query carries. A fabricated allow grant yields ALLOW just as a real
// one would. The defense is the attribute/grant-resolution trust boundary (Story 3): the
// consumer must source grants from trusted origins. The engine, by design, sees only values.
func TestByDesign_ForgedGrantIndistinguishableFromReal(t *testing.T) {
	rules := mustPolicy(t, exactAllowPolicy)

	// A grant the subject legitimately holds.
	legit := Query{Grants: []Grant{{"read", "obj1", Allow}}, Need: "read", Scope: "obj1"}
	// A grant an attacker fabricated for a capability they were never issued. Byte-for-byte
	// it is a normal grant; only its ORIGIN differs, and origin is invisible to the engine.
	forged := Query{Grants: []Grant{{"delete", "obj1", Allow}}, Need: "delete", Scope: "obj1"}

	if !evaluate(rules, legit, denyOverrides).Allow {
		t.Fatal("legit grant should be permitted (sanity)")
	}
	if !evaluate(rules, forged, denyOverrides).Allow {
		t.Error("engine permits the fabricated grant — this is faithful evaluation by design; " +
			"provenance is the perimeter's job, not the engine's")
	}
}

// Threat 9 — injection-shaped attribute values (SQL-ish, policy-fragment-ish, sigils, control
// bytes) are treated as OPAQUE strings: compared for equality only, never parsed, interpreted
// or executed. They match nothing but a literal equal to themselves.
func TestByDesign_InjectionShapedValuesAreOpaque(t *testing.T) {
	payloads := []string{
		`admin'; permit all`,    // SQL/policy injection shape
		`-x`,                    // a token some systems treat as a flag
		`{"any":[{"lit":"x"}]}`, // looks exactly like a policy condition node
		`*`,                     // a sigil to which the ENGINE assigns no meaning
		"\x00\x01ctrl",          // control bytes
		`") OR permit=true --`,  // classic injection tail
	}

	// A rule that permits only when need == "read". No payload should ever match it: the
	// payloads are inert data, compared unequal to "read".
	guard := mustPolicy(t, `[{"name":"exact-read","effect":"allow","when":{"eq":[{"attr":"need"},{"lit":"read"}]}}]`)

	for _, p := range payloads {
		q := Query{Grants: []Grant{{"tok", "", Allow}}, Need: p, Scope: ""}
		if evaluate(guard, q, denyOverrides).Allow {
			t.Errorf("payload %q was NOT treated as opaque — it matched a rule it should not", p)
		}

		// Proof of pure string equality: the very same payload matches iff the literal it is
		// compared against equals it exactly. The literal is JSON-encoded so control bytes and
		// quotes round-trip as data, never as structure.
		litJSON, err := json.Marshal(p)
		if err != nil {
			t.Fatalf("marshal payload: %v", err)
		}
		selfMatch := mustPolicy(t, `[{"name":"exact-self","effect":"allow","when":{"eq":[{"attr":"need"},{"lit":`+string(litJSON)+`}]}}]`)
		if !evaluate(selfMatch, q, denyOverrides).Allow {
			t.Errorf("payload %q should match a literal equal to itself (opaque equality)", p)
		}
	}
}
