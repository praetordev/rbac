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

type verdict struct {
	allow  bool
	reason string
}

func checkVerdict(t *testing.T, label string, d Decision, want verdict) {
	t.Helper()
	if d.Allow != want.allow || d.Reason != want.reason {
		t.Errorf("%s: got {allow=%v reason=%q}, want {allow=%v reason=%q}",
			label, d.Allow, d.Reason, want.allow, want.reason)
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
		denyOverrides verdict
		firstMatch    verdict
	}{
		{
			"global grant of the exact capability",
			Query{Grants: []Grant{{"read", "", Allow}}, Need: "read", Scope: "obj1"},
			verdict{true, "allowed by exact-global"},
			verdict{true, "ALLOW by exact-global"},
		},
		{
			"scoped grant, matching scope",
			Query{Grants: []Grant{{"read", "obj1", Allow}}, Need: "read", Scope: "obj1"},
			verdict{true, "allowed by exact-scoped"},
			verdict{true, "ALLOW by exact-scoped"},
		},
		{
			"scoped grant, different scope",
			Query{Grants: []Grant{{"read", "obj1", Allow}}, Need: "read", Scope: "obj2"},
			verdict{false, "default-deny (no rule matched)"},
			verdict{false, "default-deny (no rule matched)"},
		},
		{
			"global wildcard",
			Query{Grants: []Grant{{"*", "", Allow}}, Need: "write", Scope: "obj5"},
			verdict{true, "allowed by wildcard-global"},
			verdict{true, "ALLOW by wildcard-global"},
		},
		{
			"scoped wildcard on the scope",
			Query{Grants: []Grant{{"*", "obj3", Allow}}, Need: "read", Scope: "obj3"},
			verdict{true, "allowed by wildcard-scoped"},
			verdict{true, "ALLOW by wildcard-scoped"},
		},
		{
			// The pivotal case: a global wildcard permits, an explicit scoped deny forbids.
			// deny-overrides lets the deny win; first-match takes the earlier permit. This
			// divergence is the whole reason both strategies exist — lock it hard.
			"global wildcard + explicit scoped deny",
			Query{Grants: []Grant{{"*", "", Allow}, {"write", "obj9", Deny}}, Need: "write", Scope: "obj9"},
			verdict{false, "denied by explicit-deny"},
			verdict{true, "ALLOW by wildcard-global"},
		},
		{
			"no grants",
			Query{Grants: nil, Need: "read", Scope: "obj1"},
			verdict{false, "default-deny (no rule matched)"},
			verdict{false, "default-deny (no rule matched)"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			checkVerdict(t, "deny-overrides", evaluate(rules, tc.q, denyOverrides), tc.denyOverrides)
			checkVerdict(t, "first-match", evaluate(rules, tc.q, firstMatch), tc.firstMatch)
		})
	}
}

// TestCharacterizationStrategyDivergence pins the pivotal case at the STRUCTURAL level, not
// just the verdict: under deny-overrides the permit is provisional and the deny is
// decisive; under first-match the permit is decisive and the deny is never considered.
func TestCharacterizationStrategyDivergence(t *testing.T) {
	rules, err := parsePolicy(policyJSON)
	if err != nil {
		t.Fatalf("policy.json must parse: %v", err)
	}
	q := Query{Grants: []Grant{{"*", "", Allow}, {"write", "obj9", Deny}}, Need: "write", Scope: "obj9"}

	do := evaluate(rules, q, denyOverrides)
	if do.Allow {
		t.Fatal("deny-overrides must DENY the pivotal case")
	}
	if permit := findRule(t, do, "wildcard-global"); permit.Outcome != OutcomeAllow || permit.Decisive {
		t.Errorf("deny-overrides: wildcard-global should be a provisional (non-decisive) allow, got outcome=%v decisive=%v", permit.Outcome, permit.Decisive)
	}
	if deny := findRule(t, do, "explicit-deny"); deny.Outcome != OutcomeDeny || !deny.Decisive {
		t.Errorf("deny-overrides: explicit-deny should be the decisive deny, got outcome=%v decisive=%v", deny.Outcome, deny.Decisive)
	}

	fm := evaluate(rules, q, firstMatch)
	if !fm.Allow {
		t.Fatal("first-match must ALLOW the pivotal case")
	}
	if permit := findRule(t, fm, "wildcard-global"); permit.Outcome != OutcomeAllow || !permit.Decisive {
		t.Errorf("first-match: wildcard-global should be the decisive allow, got outcome=%v decisive=%v", permit.Outcome, permit.Decisive)
	}
	if deny := findRule(t, fm, "explicit-deny"); deny.Outcome != OutcomeSkipped {
		t.Errorf("first-match: explicit-deny should be skipped once the verdict is locked, got outcome=%v", deny.Outcome)
	}
}
