package rbac

import (
	"fmt"
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

	d := evaluate(rules, q, DenyOverrides)
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
	d := evaluate(rules, empty, DenyOverrides)
	if !d.Allow {
		t.Error("a present-empty scope should match an empty-literal comparison")
	}
	cmp := condOf(t, d)
	if cmp.Left.Absent() || !cmp.Left.Present {
		t.Errorf("scope is present-empty, not absent: %+v", cmp.Left)
	}

	// A non-empty scope is present but unequal -> no match, and NOT flagged absent.
	nonEmpty := Query{Grants: []Grant{{"tok", "", Allow}}, Need: "read", Scope: "obj1"}
	d2 := evaluate(rules, nonEmpty, DenyOverrides)
	if d2.Allow {
		t.Error("scope=obj1 must not match lit(\"\")")
	}
	if c := condOf(t, d2); c.Left.Absent() {
		t.Error("a present non-empty scope must not be flagged absent")
	}
}

// Corrected contract (was TestKnownDeviation_AbsentCollapsesToEmpty): absent is now a
// NON-MATCH against every concrete value, INCLUDING the empty literal. The verdict — not just
// the trace — distinguishes absent from present-empty:
//   - absent == lit("")        -> non-match (was ALLOW under the old absent->"" coercion)
//   - present("") == lit("")   -> match
//
// This is the tested guarantee of the epic invariant "absent -> comparison false".
func TestAbsentIsNonMatchEvenAgainstEmptyLiteral(t *testing.T) {
	rule := `[{"name":"r","effect":"allow","when":{"eq":[{"attr":"%s"},{"lit":""}]}}]`

	// Absent attribute vs empty literal -> DENY (the fix; previously ALLOW).
	absent := mustPolicy(t, fmt.Sprintf(rule, "subject.dept"))
	dAbsent := evaluate(absent, Query{Grants: []Grant{{"tok", "", Allow}}, Need: "read", Scope: "obj1"}, DenyOverrides)
	if dAbsent.Allow {
		t.Error("absent attribute must NOT match an empty literal (absent is a non-match against all concrete values)")
	}
	if cmp := condOf(t, dAbsent); !cmp.Left.Absent() {
		t.Error("trace must still mark the operand absent")
	}

	// Present-but-empty attribute vs empty literal -> ALLOW (unchanged).
	present := mustPolicy(t, fmt.Sprintf(rule, "scope"))
	dPresent := evaluate(present, Query{Grants: []Grant{{"tok", "", Allow}}, Need: "read", Scope: ""}, DenyOverrides)
	if !dPresent.Allow {
		t.Error("present-empty attribute must still match an empty literal")
	}
}

// Operator audit: the absent-handling rule (an absent operand -> unknown -> non-match, and
// unknown propagates by Kleene logic) applied to every operator that could otherwise coerce
// absent to "". Each row pins the corrected behavior.
func TestAbsentOperatorAudit(t *testing.T) {
	// need is present ("read"); subject.dept is absent throughout.
	q := Query{Grants: []Grant{{"tok", "", Allow}}, Need: "read", Scope: "obj1"}

	cases := []struct {
		name      string
		when      string
		wantAllow bool
		note      string
	}{
		{
			"!= with absent operand",
			`{"ne":[{"attr":"subject.dept"},{"lit":"x"}]}`,
			false,
			"absent != x is unknown, not true (was: absent coerced to \"\" made \"\" != \"x\" TRUE)",
		},
		{
			"not over absent comparison (negation trap)",
			`{"not":{"eq":[{"attr":"subject.dept"},{"lit":"x"}]}}`,
			false,
			"not(unknown) = unknown, not true (was: not(false) = TRUE)",
		},
		{
			"and with an absent branch",
			`{"all":[{"eq":[{"attr":"need"},{"lit":"read"}]},{"eq":[{"attr":"subject.dept"},{"lit":"x"}]}]}`,
			false,
			"true AND unknown = unknown -> non-match (fails closed on missing data)",
		},
		{
			"or tolerates absent when another branch is true",
			`{"any":[{"eq":[{"attr":"need"},{"lit":"read"}]},{"eq":[{"attr":"subject.dept"},{"lit":"x"}]}]}`,
			true,
			"true OR unknown = true -> a present, satisfied branch still matches",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rules := mustPolicy(t, `[{"name":"r","effect":"allow","when":`+tc.when+`}]`)
			if got := evaluate(rules, q, DenyOverrides).Allow; got != tc.wantAllow {
				t.Errorf("allow = %v, want %v — %s", got, tc.wantAllow, tc.note)
			}
		})
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
	if !evaluate(rules, Query{Grants: []Grant{{"tok", "", Allow}}, Need: "read", Scope: ""}, DenyOverrides).Allow {
		t.Error("a null literal should collapse to the empty string and match a present-empty scope")
	}
	if evaluate(rules, Query{Grants: []Grant{{"tok", "", Allow}}, Need: "read", Scope: "obj1"}, DenyOverrides).Allow {
		t.Error("null-literal-as-empty must not match a non-empty scope")
	}
}
