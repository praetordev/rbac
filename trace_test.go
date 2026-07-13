package rbac

import (
	"strings"
	"testing"
)

// findRule locates a rule's trace by name.
func findRule(t *testing.T, d Decision, name string) RuleTrace {
	t.Helper()
	for _, rt := range d.trace {
		if rt.Name == name {
			return rt
		}
	}
	t.Fatalf("no rule %q in trace", name)
	return RuleTrace{}
}

// 1. A deny caused by an absent attribute reports "absent", distinctly from a
// present-but-unequal comparison in the same decision.
func TestAbsentAttributeShowsAbsentNotUnequal(t *testing.T) {
	// A rule that matches if either the need equals "delete" (present, may be unequal)
	// OR the subject's department equals "sales" (subject.dept is NOT an attribute this
	// engine exposes — it is ABSENT). Using `or` forces both comparisons to be evaluated.
	rules := []Rule{{
		Name:   "elevated",
		Effect: Allow,
		Cond: or(
			eq(attr("need"), lit("delete")),
			eq(attr("subject.dept"), lit("sales")),
		),
	}}
	q := Query{Grants: []Grant{{"read", "obj1", Allow}}, Need: "read", Scope: "obj1"}

	d := evaluate(rules, q, DenyOverrides)
	if d.Allow {
		t.Fatal("expected DENY (neither branch holds)")
	}

	rt := findRule(t, d, "elevated")
	or := rt.Attempts[0].Cond // the OR node evaluated against the single grant
	if or.Kind != "bool" || or.Op != "or" || or.Result {
		t.Fatalf("expected a false OR node, got %+v", or)
	}

	needCmp, deptCmp := or.Kids[0], or.Kids[1]

	// The need comparison is present-but-unequal: both operands present, result false, and
	// NOT flagged absent.
	if needCmp.Left.Absent() || !needCmp.Left.Present || needCmp.Result {
		t.Errorf("need comparison should be present-but-unequal, got %+v", needCmp.Left)
	}
	if absentOperands(needCmp) != "" {
		t.Errorf("need comparison must not be flagged absent, got %q", absentOperands(needCmp))
	}

	// The dept comparison is ABSENT: the attribute is not present.
	if !deptCmp.Left.Absent() {
		t.Errorf("subject.dept must be absent, got %+v", deptCmp.Left)
	}
	if absentOperands(deptCmp) != "subject.dept" {
		t.Errorf("dept comparison should name the absent attr, got %q", absentOperands(deptCmp))
	}

	// The human render must make the absence explicit and must not mislabel the unequal
	// comparison as absent.
	out := d.Explain()
	if !strings.Contains(out, "absent(subject.dept)") || !strings.Contains(out, "subject.dept=<absent>") {
		t.Errorf("render does not surface the absent attribute:\n%s", out)
	}
	for _, line := range strings.Split(out, "\n") {
		if strings.Contains(line, "need=") && strings.Contains(line, "absent") {
			t.Errorf("present-but-unequal need comparison mislabelled absent:\n%s", line)
		}
	}
}

// 2. Under deny-overrides, the trace shows a denying rule beating a permitting one: both
// match, the permit is provisional, the deny is decisive, and the verdict is DENY.
func TestDenyOverridesTraceShowsDenyBeatingPermit(t *testing.T) {
	rules := []Rule{
		{
			Name:   "allow-wildcard",
			Effect: Allow,
			Cond:   eq(attr("grant.cap"), lit("*")),
		},
		{
			Name:   "deny-scoped",
			Effect: Deny,
			Cond: and(
				eq(attr("grant.effect"), lit("deny")),
				eq(attr("grant.cap"), attr("need")),
				eq(attr("grant.scope"), attr("scope")),
			),
		},
	}
	q := Query{
		Grants: []Grant{{"*", "", Allow}, {"write", "obj9", Deny}},
		Need:   "write",
		Scope:  "obj9",
	}

	d := evaluate(rules, q, DenyOverrides)
	if d.Allow {
		t.Fatal("deny-overrides must DENY when a deny rule matches")
	}

	permit := findRule(t, d, "allow-wildcard")
	if permit.Outcome != OutcomeAllow {
		t.Errorf("allow-wildcard outcome = %v, want allow", permit.Outcome)
	}
	if permit.Decisive {
		t.Error("a provisional allow under deny-overrides must not be decisive")
	}

	deny := findRule(t, d, "deny-scoped")
	if deny.Outcome != OutcomeDeny {
		t.Errorf("deny-scoped outcome = %v, want deny", deny.Outcome)
	}
	if !deny.Decisive {
		t.Error("the deny that wins must be marked decisive")
	}

	out := d.Explain()
	if !strings.Contains(out, "deny-scoped denied, overriding permit from allow-wildcard") {
		t.Errorf("render does not explain deny beating permit:\n%s", out)
	}
}

// 3. The trace names the snapshot id that produced the decision (ties to the snapshot step).
func TestTraceNamesSnapshotID(t *testing.T) {
	v2 := mustSnap(t, "v2", policyV2JSON, DenyOverrides)
	d := Decide(v2, writeReq())

	if d.Trace().Snapshot != "v2" {
		t.Errorf("structured Trace.Snapshot = %q, want v2", d.Trace().Snapshot)
	}
	if !strings.Contains(d.Explain(), "snapshot v2") {
		t.Errorf("render does not name snapshot v2:\n%s", d.Explain())
	}
}

// 4. Tracing has no effect on the verdict: the trace-on fold (evaluate) and the trace-off
// fold (evalVerdict) reach the identical decision for every query and strategy.
func TestTraceOnVsTraceOffIdenticalDecision(t *testing.T) {
	rules, err := parsePolicy(policyJSON)
	if err != nil {
		t.Fatal(err)
	}
	queries := []Query{
		{Grants: []Grant{{"read", "", Allow}}, Need: "read", Scope: "obj1"},
		{Grants: []Grant{{"read", "obj1", Allow}}, Need: "read", Scope: "obj2"},
		{Grants: []Grant{{"*", "", Allow}}, Need: "write", Scope: "obj5"},
		{Grants: []Grant{{"*", "", Allow}, {"write", "obj9", Deny}}, Need: "write", Scope: "obj9"},
		{Grants: nil, Need: "read", Scope: "obj1"},
	}
	strategies := map[string]Strategy{"deny-overrides": DenyOverrides, "first-match": FirstMatch}

	for name, combine := range strategies {
		for i, q := range queries {
			on := evaluate(rules, q, combine)
			off := evalVerdict(rules, q, combine)
			if on.Allow != off.Allow || on.Reason != off.Reason {
				t.Errorf("[%s q%d] trace-on {%v,%q} != trace-off {%v,%q}",
					name, i, on.Allow, on.Reason, off.Allow, off.Reason)
			}
			onRef, onOK := on.Decider()
			offRef, offOK := off.Decider()
			if onRef != offRef || onOK != offOK {
				t.Errorf("[%s q%d] trace-on decider {%+v,%v} != trace-off {%+v,%v}",
					name, i, onRef, onOK, offRef, offOK)
			}
			if on.trace == nil {
				t.Errorf("[%s q%d] trace-on produced no trace", name, i)
			}
			if off.trace != nil {
				t.Errorf("[%s q%d] trace-off must build no trace", name, i)
			}
		}
	}
}

// Guard: the traced condition evaluators mirror the decision-path evaluators exactly, so a
// trace can never claim a result the verdict disagrees with.
func TestTracedEvalMatchesPureEval(t *testing.T) {
	rules, err := parsePolicy(policyJSON)
	if err != nil {
		t.Fatal(err)
	}
	queries := []Query{
		{Grants: []Grant{{"read", "", Allow}}, Need: "read", Scope: "obj1"},
		{Grants: []Grant{{"read", "obj1", Allow}}, Need: "read", Scope: "obj1"},
		{Grants: []Grant{{"*", "obj3", Allow}}, Need: "read", Scope: "obj3"},
		{Grants: []Grant{{"*", "", Allow}, {"write", "obj9", Deny}}, Need: "write", Scope: "obj9"},
	}
	for _, r := range rules {
		for _, q := range queries {
			wantMatch := matches(r.Cond, q)
			gotMatch, attempts := traceMatch(r.Cond, q)
			if wantMatch != gotMatch {
				t.Errorf("rule %q: traceMatch=%v matches=%v", r.Name, gotMatch, wantMatch)
			}
			for _, g := range q.Grants {
				e := env{q: q, g: g}
				if got := traceCond(r.Cond, e).Result; got != evalBool(r.Cond, e) {
					t.Errorf("rule %q grant %+v: traceCond=%v evalBool=%v", r.Name, g, got, evalBool(r.Cond, e))
				}
			}
			_ = attempts
		}
	}
}
