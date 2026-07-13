package main

import (
	"strings"
	"testing"
)

// Story 1 (bound the parser): a technically valid but pathological policy must be rejected
// at parse time within a bounded envelope — never crash, stack-overflow, or hang — and a
// bad load must fail closed to the last known-good snapshot. These are the engine's only
// input-distrust, and only because they guard its own liveness, not the meaning of input.

// nestedAllPolicy builds a policy whose single rule nests `depth` "all" conditions around a
// trivial leaf. Used to exercise the depth bound.
func nestedAllPolicy(depth int) []byte {
	open := strings.Repeat(`{"all":[`, depth)
	closed := strings.Repeat(`]}`, depth)
	when := open + `{"eq":[{"lit":"a"},{"lit":"b"}]}` + closed
	return []byte(`[{"name":"deep","effect":"allow","when":` + when + `}]`)
}

// wideAllPolicy builds a policy whose single rule is one "all" with `n` comparison operands.
// Used to exercise the total-node-count bound (width, not depth).
func wideAllPolicy(n int) []byte {
	op := `{"eq":[{"lit":"x"},{"lit":"y"}]}`
	ops := make([]string, n)
	for i := range ops {
		ops[i] = op
	}
	return []byte(`[{"name":"wide","effect":"allow","when":{"all":[` + strings.Join(ops, ",") + `]}}]`)
}

func TestParserRejectsDeepNesting(t *testing.T) {
	// Thousands of nested conditions — well past the JSON scanner's own limit is not needed;
	// the engine's depth bound must fire first, and it must return an error, not panic.
	_, err := parsePolicy(nestedAllPolicy(2000))
	if err == nil {
		t.Fatal("deeply nested policy must be rejected")
	}
	if !strings.Contains(err.Error(), "depth") {
		t.Errorf("expected a depth error, got: %v", err)
	}
}

func TestParserRejectsWideNodeCount(t *testing.T) {
	// 4000 comparisons => ~12001 nodes, past maxNodes, but shallow — depth alone wouldn't
	// catch it.
	_, err := parsePolicy(wideAllPolicy(4000))
	if err == nil {
		t.Fatal("policy exceeding the node budget must be rejected")
	}
	if !strings.Contains(err.Error(), "condition nodes") {
		t.Errorf("expected a node-count error, got: %v", err)
	}
}

func TestParserRejectsTooManyRules(t *testing.T) {
	rules := make([]string, maxRules+1)
	for i := range rules {
		rules[i] = `{"name":"r","effect":"allow","when":{"lit":"x"}}`
	}
	_, err := parsePolicy([]byte("[" + strings.Join(rules, ",") + "]"))
	if err == nil {
		t.Fatal("policy exceeding the rule limit must be rejected")
	}
	if !strings.Contains(err.Error(), "rules") {
		t.Errorf("expected a rule-count error, got: %v", err)
	}
}

func TestParserRejectsHugeLiteral(t *testing.T) {
	big := strings.Repeat("a", maxLiteralLen+1)
	_, err := parsePolicy([]byte(`[{"name":"r","effect":"allow","when":{"lit":"` + big + `"}}]`))
	if err == nil {
		t.Fatal("oversized literal must be rejected")
	}
	if !strings.Contains(err.Error(), "lit") {
		t.Errorf("expected a literal-size error, got: %v", err)
	}
}

func TestParserRejectsOversizedDocument(t *testing.T) {
	// The size gate runs before JSON parsing, so the content need not be valid.
	_, err := parsePolicy(make([]byte, maxPolicyBytes+1))
	if err == nil {
		t.Fatal("oversized document must be rejected")
	}
	if !strings.Contains(err.Error(), "bytes") {
		t.Errorf("expected a size error, got: %v", err)
	}
}

// Zero-key and two-key condition objects are distinct authoring mistakes and must produce
// distinct, actionable errors rather than a silent dispatch on an arbitrary key.
func TestParserZeroKeyVsMultiKeyDistinctErrors(t *testing.T) {
	_, zeroErr := parsePolicy([]byte(`[{"name":"z","effect":"allow","when":{}}]`))
	_, multiErr := parsePolicy([]byte(`[{"name":"m","effect":"allow","when":{"eq":[{"lit":"a"},{"lit":"b"}],"ne":[{"lit":"a"},{"lit":"b"}]}}]`))

	if zeroErr == nil || multiErr == nil {
		t.Fatalf("both must error; got zero=%v multi=%v", zeroErr, multiErr)
	}
	if zeroErr.Error() == multiErr.Error() {
		t.Fatalf("zero-key and multi-key must be distinguishable, both said: %v", zeroErr)
	}
	if !strings.Contains(zeroErr.Error(), "no keys") {
		t.Errorf("zero-key error should say 'no keys', got: %v", zeroErr)
	}
	if !strings.Contains(multiErr.Error(), "2 keys") {
		t.Errorf("multi-key error should report the key count, got: %v", multiErr)
	}
}

func TestParserClearErrorsForMalformed(t *testing.T) {
	cases := []struct {
		name, policy, wantSubstr string
	}{
		{"unknown node type", `[{"name":"r","effect":"allow","when":{"xyz":"nope"}}]`, `unknown condition "xyz"`},
		{"wrong operand count", `[{"name":"r","effect":"allow","when":{"eq":[{"lit":"a"}]}}]`, "needs exactly 2 operands"},
		{"empty all", `[{"name":"r","effect":"allow","when":{"all":[]}}]`, "needs at least one operand"},
		{"bad effect", `[{"name":"r","effect":"maybe","when":{"lit":"x"}}]`, "effect must be"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := parsePolicy([]byte(tc.policy))
			if err == nil {
				t.Fatalf("expected an error for %s", tc.name)
			}
			if !strings.Contains(err.Error(), tc.wantSubstr) {
				t.Errorf("error for %s = %q, want substring %q", tc.name, err, tc.wantSubstr)
			}
		})
	}
}

// A rejected load must not disturb the installed snapshot: evaluation keeps serving the last
// known-good policy and never opens access.
func TestBadLoadFailsClosedToLastKnownGood(t *testing.T) {
	readReq := Query{Grants: []Grant{{"read", "obj1", Allow}}, Need: "read", Scope: "obj1"}

	v1 := mustSnap(t, "v1", policyV1JSON, denyOverrides)
	h := NewHolder(v1)

	if err := h.Load("v-bad", nestedAllPolicy(2000), denyOverrides); err == nil {
		t.Fatal("a pathological bundle must be rejected by Load")
	}
	if cur := h.Current(); cur == nil || cur.ID() != "v1" {
		t.Fatalf("rejected load must keep last known-good v1, got %v", cur)
	}
	if !h.Decide(readReq).Allow {
		t.Error("v1 must still ALLOW read after a rejected load")
	}
	if h.Decide(writeReq()).Allow {
		t.Error("v1 must still DENY write after a rejected load (no accidental open)")
	}

	// A good load through the same path installs normally.
	if err := h.Load("v2", policyV2JSON, denyOverrides); err != nil {
		t.Fatalf("valid bundle should load: %v", err)
	}
	if !h.Decide(writeReq()).Allow || h.Decide(writeReq()).Snapshot != "v2" {
		t.Error("after a valid load, v2 must serve and ALLOW write")
	}
}

// With no known-good snapshot installed, a bad load leaves the holder empty and evaluation
// fails closed to deny — never opens, never panics.
func TestBadLoadWithNoKnownGoodStaysClosed(t *testing.T) {
	var empty Holder
	if err := empty.Load("bad", nestedAllPolicy(2000), denyOverrides); err == nil {
		t.Fatal("bad load should error")
	}
	if empty.Current() != nil {
		t.Fatal("a rejected first load must leave the holder empty")
	}
	if empty.Decide(writeReq()).Allow {
		t.Error("empty holder must fail closed to DENY")
	}
}
