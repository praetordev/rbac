package main

import "testing"

// This file PINS the prototype's current behaviour. Every case here was previously only
// eyeballed in the `go run` demo (the seven capability cases in main.go under both
// combining strategies, and the shape of the embedded fixture). Locking them turns the
// demo into a regression net and forces a verdict: the prototype's behaviour is now
// defined by assertions, not by reading output. If a later change (the adversarial epic
// included) shifts any decision, these tests fail loudly and deliberately.
//
// Reasons are pinned verbatim: the Reason string is part of the observable decision, so a
// change to it is a behaviour change we want surfaced, not smuggled in.

// event is the REAL observable decision: did it permit, which rule decided, and with what
// effect. It deliberately does NOT include the Reason prose — that string is a rendering of
// this same event, so pinning it would lock incidental wording as if it were behaviour.
//
// The deciding rule is authored here by NAME for readability, but the assertion keys on the
// decision's stable rule ID (via Decision.Decider), resolving the name against the fixture.
// Names are unique in this fixture (pinned by TestCharacterizationFixtureShape); the ID is
// what makes "which rule decided" unambiguous even if they weren't.
type event struct {
	allow   bool
	decider string // fixture rule NAME; "" means no rule decided (default-deny)
	effect  Effect // meaningful only when decider != ""
}

// idOf resolves a fixture rule name to its stable ID.
func idOf(t *testing.T, rules []Rule, name string) int {
	t.Helper()
	for _, r := range rules {
		if r.Name == name {
			return r.ID
		}
	}
	t.Fatalf("fixture has no rule named %q", name)
	return -1
}

func checkEvent(t *testing.T, label string, rules []Rule, d Decision, want event) {
	t.Helper()
	ref, decided := d.Decider()

	if d.Allow != want.allow {
		t.Errorf("%s: allow = %v, want %v", label, d.Allow, want.allow)
	}
	if want.decider == "" {
		if decided {
			t.Errorf("%s: expected no decider (default-deny), got rule %d %q", label, ref.ID, ref.Name)
		}
		return
	}
	if !decided {
		t.Errorf("%s: expected deciding rule %q, got none", label, want.decider)
		return
	}
	if wantID := idOf(t, rules, want.decider); ref.ID != wantID {
		t.Errorf("%s: deciding rule id = %d (%q), want %d (%q)", label, ref.ID, ref.Name, wantID, want.decider)
	}
	if ref.Effect != want.effect {
		t.Errorf("%s: deciding effect = %v, want %v", label, ref.Effect, want.effect)
	}
}

// TestCharacterizationFixtureShape locks the embedded policy.json: rule count, order,
// names, and effects. The whole capability suite is meaningless if the fixture drifts.
func TestCharacterizationFixtureShape(t *testing.T) {
	rules, err := parsePolicy(policyJSON)
	if err != nil {
		t.Fatalf("policy.json must parse: %v", err)
	}
	want := []struct {
		name   string
		effect Effect
	}{
		{"wildcard-global", Allow},
		{"exact-global", Allow},
		{"wildcard-scoped", Allow},
		{"exact-scoped", Allow},
		{"explicit-deny", Deny},
	}
	if len(rules) != len(want) {
		t.Fatalf("rule count = %d, want %d", len(rules), len(want))
	}
	for i, w := range want {
		if rules[i].Name != w.name || rules[i].Effect != w.effect {
			t.Errorf("rule %d = {%q %v}, want {%q %v}", i, rules[i].Name, rules[i].Effect, w.name, w.effect)
		}
	}
}

// TestCharacterizationCapabilitySuite pins the seven demo cases under both strategies,
// against the real embedded policy.json.
func TestCharacterizationCapabilitySuite(t *testing.T) {
	rules, err := parsePolicy(policyJSON)
	if err != nil {
		t.Fatalf("policy.json must parse: %v", err)
	}

	cases := []struct {
		name          string
		q             Query
		denyOverrides event
		firstMatch    event
	}{
		{
			"global grant of the exact capability",
			Query{Grants: []Grant{{"read", "", Allow}}, Need: "read", Scope: "obj1"},
			event{allow: true, decider: "exact-global", effect: Allow},
			event{allow: true, decider: "exact-global", effect: Allow},
		},
		{
			"scoped grant, matching scope",
			Query{Grants: []Grant{{"read", "obj1", Allow}}, Need: "read", Scope: "obj1"},
			event{allow: true, decider: "exact-scoped", effect: Allow},
			event{allow: true, decider: "exact-scoped", effect: Allow},
		},
		{
			"scoped grant, different scope",
			Query{Grants: []Grant{{"read", "obj1", Allow}}, Need: "read", Scope: "obj2"},
			event{allow: false, decider: ""}, // default-deny: no rule decided
			event{allow: false, decider: ""},
		},
		{
			"global wildcard",
			Query{Grants: []Grant{{"*", "", Allow}}, Need: "write", Scope: "obj5"},
			event{allow: true, decider: "wildcard-global", effect: Allow},
			event{allow: true, decider: "wildcard-global", effect: Allow},
		},
		{
			"scoped wildcard on the scope",
			Query{Grants: []Grant{{"*", "obj3", Allow}}, Need: "read", Scope: "obj3"},
			event{allow: true, decider: "wildcard-scoped", effect: Allow},
			event{allow: true, decider: "wildcard-scoped", effect: Allow},
		},
		{
			// The pivotal case: a global wildcard permits, an explicit scoped deny forbids.
			// deny-overrides lets the deny win; first-match takes the earlier permit. This
			// divergence is the whole reason both strategies exist — lock it hard.
			"global wildcard + explicit scoped deny",
			Query{Grants: []Grant{{"*", "", Allow}, {"write", "obj9", Deny}}, Need: "write", Scope: "obj9"},
			event{allow: false, decider: "explicit-deny", effect: Deny},
			event{allow: true, decider: "wildcard-global", effect: Allow},
		},
		{
			"no grants",
			Query{Grants: nil, Need: "read", Scope: "obj1"},
			event{allow: false, decider: ""},
			event{allow: false, decider: ""},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			checkEvent(t, "deny-overrides", rules, evaluate(rules, tc.q, denyOverrides), tc.denyOverrides)
			checkEvent(t, "first-match", rules, evaluate(rules, tc.q, firstMatch), tc.firstMatch)
		})
	}
}

// TestCharacterizationStrategyDivergence pins the pivotal case: a global wildcard permits
// while an explicit scoped deny forbids. The two strategies disagree, and the disagreement
// is the whole reason both exist. Expressed as the real event — a different rule decides,
// with a different effect and verdict — not as internal Outcome/Decisive flags.
func TestCharacterizationStrategyDivergence(t *testing.T) {
	rules, err := parsePolicy(policyJSON)
	if err != nil {
		t.Fatalf("policy.json must parse: %v", err)
	}
	q := Query{Grants: []Grant{{"*", "", Allow}, {"write", "obj9", Deny}}, Need: "write", Scope: "obj9"}

	// deny-overrides: the deny wins.
	checkEvent(t, "deny-overrides", rules, evaluate(rules, q, denyOverrides),
		event{allow: false, decider: "explicit-deny", effect: Deny})

	// first-match: the earlier permit wins; the deny never decides.
	checkEvent(t, "first-match", rules, evaluate(rules, q, firstMatch),
		event{allow: true, decider: "wildcard-global", effect: Allow})
}
