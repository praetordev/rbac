package main

import (
	"strings"
	"testing"
)

// Story 3 (attribute trust contract): tests over absent / empty / null attributes confirming
// predictable, distinct behaviour and correct trace rendering. These pin the actual engine
// behaviour that the integration guide's attribute trust contract (see
// epic-rbac/INTEGRATION.md) documents for consumers we will never meet. No engine code is
// added — the behaviour already exists; here it is characterised.

// condOf returns the condition trace of a single-rule decision's first (only) grant attempt.
func condOf(t *testing.T, d Decision) *CondTrace {
	t.Helper()
	tr := d.Trace()
	if len(tr.Rules) == 0 || len(tr.Rules[0].Attempts) == 0 {
		t.Fatalf("expected one rule with one attempt, got %+v", tr.Rules)
	}
	return tr.Rules[0].Attempts[0].Cond
}

// Absent attribute vs a concrete value: comparison is FALSE, and the trace marks the
// operand absent (visibly distinct from a present-but-unequal value).
func TestAttributeAbsentComparesFalseAgainstConcrete(t *testing.T) {
	rules := mustPolicy(t, `[{"name":"r","effect":"allow","when":{"eq":[{"attr":"subject.dept"},{"lit":"sales"}]}}]`)
	q := Query{Grants: []Grant{{"tok", "", Allow}}, Need: "read", Scope: "obj1"}

	d := evaluate(rules, q, denyOverrides)
	if d.Allow {
		t.Fatal("an absent attribute must not match a concrete value")
	}

	cmp := condOf(t, d)
	if !cmp.Left.Absent() {
		t.Errorf("subject.dept should be absent, got %+v", cmp.Left)
	}
	if out := d.Explain(); !strings.Contains(out, "subject.dept=<absent>") || !strings.Contains(out, "absent(subject.dept)") {
		t.Errorf("trace must render the attribute as absent:\n%s", out)
	}
}

// A present-but-empty attribute (e.g. scope on a global check) is DISTINCT from absent: it is
// present, its value is "", and it matches an empty-literal comparison — while a non-empty
// value does not.
func TestAttributeEmptyIsPresentDistinctFromAbsent(t *testing.T) {
	rules := mustPolicy(t, `[{"name":"r","effect":"allow","when":{"eq":[{"attr":"scope"},{"lit":""}]}}]`)

	// scope is present and empty -> matches lit("").
	empty := Query{Grants: []Grant{{"tok", "", Allow}}, Need: "read", Scope: ""}
	d := evaluate(rules, empty, denyOverrides)
	if !d.Allow {
		t.Error("a present-empty scope should match an empty-literal comparison")
	}
	cmp := condOf(t, d)
	if cmp.Left.Absent() || !cmp.Left.Present {
		t.Errorf("scope is present-empty, not absent: %+v", cmp.Left)
	}

	// A non-empty scope is present but unequal -> no match, and NOT flagged absent.
	nonEmpty := Query{Grants: []Grant{{"tok", "", Allow}}, Need: "read", Scope: "obj1"}
	d2 := evaluate(rules, nonEmpty, denyOverrides)
	if d2.Allow {
		t.Error("scope=obj1 must not match lit(\"\")")
	}
	if c := condOf(t, d2); c.Left.Absent() {
		t.Error("a present non-empty scope must not be flagged absent")
	}
}

// KNOWN DEVIATION from the epic invariant "absent -> comparison false".
//
// The engine currently reads an absent attribute as "" in the decision path, so
// `attr == lit("")` returns TRUE — an absent attribute is indistinguishable from a present
// empty one in the VERDICT (only the trace separates them). A rule meant to match "present
// but empty" therefore silently also matches every subject that lacks the attribute, and the
// verdict looks identical to the intended case.
//
// This test PINS that wrong behaviour as-is, so the fix can be proven to flip exactly this
// and nothing else. It is expected to be updated once absent is corrected to a non-match.
func TestKnownDeviation_AbsentCollapsesToEmpty(t *testing.T) {
	rules := mustPolicy(t, `[{"name":"r","effect":"allow","when":{"eq":[{"attr":"subject.dept"},{"lit":""}]}}]`)
	q := Query{Grants: []Grant{{"tok", "", Allow}}, Need: "read", Scope: "obj1"}

	d := evaluate(rules, q, denyOverrides)
	if !d.Allow {
		t.Error("KNOWN DEVIATION: absent attribute is read as \"\" and so equals the empty literal (currently ALLOW)")
	}
	if cmp := condOf(t, d); !cmp.Left.Absent() {
		t.Error("the trace still marks the attribute absent, distinguishing it from a present empty")
	}
}

// null handling is predictable: a null CONDITION is rejected at parse (fail closed), while a
// JSON null in a value position collapses to the empty string (Go's json unmarshal of null
// into string yields ""). Documented so integrators are not surprised.
func TestNullAttributeHandlingIsPredictable(t *testing.T) {
	// null condition -> rejected (zero-key error), never silently treated as a match.
	if _, err := parsePolicy([]byte(`[{"name":"r","effect":"allow","when":null}]`)); err == nil {
		t.Error("a null condition must be rejected at parse (fail closed)")
	}

	// null literal -> parses as the empty string; behaves exactly like {"lit":""}.
	rules := mustPolicy(t, `[{"name":"r","effect":"allow","when":{"eq":[{"attr":"scope"},{"lit":null}]}}]`)
	if !evaluate(rules, Query{Grants: []Grant{{"tok", "", Allow}}, Need: "read", Scope: ""}, denyOverrides).Allow {
		t.Error("a null literal should collapse to the empty string and match a present-empty scope")
	}
	if evaluate(rules, Query{Grants: []Grant{{"tok", "", Allow}}, Need: "read", Scope: "obj1"}, denyOverrides).Allow {
		t.Error("null-literal-as-empty must not match a non-empty scope")
	}
}
