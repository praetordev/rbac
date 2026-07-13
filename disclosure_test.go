package rbac

import (
	"strings"
	"testing"
)

// Story 5 (trace disclosure levels): the full trace (for the app's logs) must capture the
// complete rationale, the minimal reason (for end users) must reveal no structure, and
// building/rendering either must not change the decision.

// mainSnap is a snapshot of the embedded capability policy, used to produce structured
// decisions with a real snapshot id.
func mainSnap(t *testing.T) *Snapshot {
	t.Helper()
	return mustSnap(t, "main", policyJSON, DenyOverrides)
}

// Every DENY, whatever its cause, discloses the identical minimal reason; likewise every
// PERMIT. An end user therefore cannot tell a default-deny from an explicit-deny, an
// absent-attribute deny, or a fail-closed deny — no probing signal leaks.
func TestMinimalReasonConstantAcrossCauses(t *testing.T) {
	rules, err := parsePolicy(policyJSON)
	if err != nil {
		t.Fatal(err)
	}
	absentRule := mustPolicy(t, `[{"name":"r","effect":"allow","when":{"eq":[{"attr":"subject.dept"},{"lit":"x"}]}}]`)

	denials := map[string]Decision{
		"default-deny":  evaluate(rules, Query{Grants: []Grant{{"read", "obj1", Allow}}, Need: "read", Scope: "obj2"}, DenyOverrides),
		"explicit-deny": evaluate(rules, Query{Grants: []Grant{{"*", "", Allow}, {"write", "obj9", Deny}}, Need: "write", Scope: "obj9"}, DenyOverrides),
		"absent-attr":   evaluate(absentRule, Query{Grants: []Grant{{"tok", "", Allow}}, Need: "read", Scope: "obj1"}, DenyOverrides),
		"fail-closed":   Decide(nil, Query{Need: "read"}),
	}
	for name, d := range denials {
		if d.Allow {
			t.Fatalf("%s should be a denial (test setup)", name)
		}
		if got := d.Disclose(Minimal); got != "access denied" {
			t.Errorf("%s minimal reason = %q, want the constant \"access denied\"", name, got)
		}
	}

	permits := map[string]Decision{
		"exact":    evaluate(rules, Query{Grants: []Grant{{"read", "", Allow}}, Need: "read", Scope: "obj1"}, DenyOverrides),
		"wildcard": evaluate(rules, Query{Grants: []Grant{{"*", "", Allow}}, Need: "write", Scope: "obj5"}, DenyOverrides),
	}
	for name, d := range permits {
		if !d.Allow {
			t.Fatalf("%s should be a permit (test setup)", name)
		}
		if got := d.Disclose(Minimal); got != "access permitted" {
			t.Errorf("%s minimal reason = %q, want the constant \"access permitted\"", name, got)
		}
	}

	if evaluate(rules, Query{}, DenyOverrides).Disclose(Minimal) == permits["exact"].Disclose(Minimal) {
		t.Error("permit and deny minimal reasons must differ")
	}
}

// The minimal reason must contain none of the structural tokens that would let an attacker
// infer the ruleset — while the full disclosure of the SAME decision does contain them.
func TestMinimalReasonLeaksNoStructure(t *testing.T) {
	d := Decide(mainSnap(t), Query{
		Grants: []Grant{{"*", "", Allow}, {"write", "obj9", Deny}},
		Need:   "write", Scope: "obj9",
	})
	if d.Allow {
		t.Fatal("expected a denial for this setup")
	}

	minimal := d.Disclose(Minimal)
	structural := []string{
		"explicit-deny", "wildcard-global", "exact-scoped", // rule names
		"main",                                              // snapshot id
		"snapshot",                                          // section labels
		"absent", "no-match", "grant.", "scope=", "==", "→", // node/trace structure
		"denied by", // internal reason prose
	}
	for _, tok := range structural {
		if strings.Contains(minimal, tok) {
			t.Errorf("minimal reason leaks structural token %q: %q", tok, minimal)
		}
	}

	// Positive contrast: the full disclosure of the same decision DOES expose structure.
	full := d.Disclose(Full)
	for _, tok := range []string{"explicit-deny", "main"} {
		if !strings.Contains(full, tok) {
			t.Errorf("full disclosure should contain %q:\n%s", tok, full)
		}
	}
}

// The full disclosure captures the complete rationale required by the epic: the deciding
// snapshot id, and absent rendered distinctly from present-but-unequal.
func TestFullDisclosureCapturesRationale(t *testing.T) {
	// A rule that compares a present attribute (unequal) and an absent one, under a snapshot.
	snap := mustSnap(t, "v-audit",
		[]byte(`[{"name":"r","effect":"allow","when":{"any":[
			{"eq":[{"attr":"need"},{"lit":"delete"}]},
			{"eq":[{"attr":"subject.dept"},{"lit":"sales"}]}
		]}}]`), DenyOverrides)
	d := Decide(snap, Query{Grants: []Grant{{"tok", "", Allow}}, Need: "read", Scope: "obj1"})

	full := d.Disclose(Full)
	if !strings.Contains(full, "v-audit") {
		t.Errorf("full disclosure must name the deciding snapshot id:\n%s", full)
	}
	if !strings.Contains(full, "subject.dept=<absent>") || !strings.Contains(full, "absent(subject.dept)") {
		t.Errorf("full disclosure must render absent distinctly:\n%s", full)
	}
	if !strings.Contains(full, `need="read"`) {
		t.Errorf("full disclosure must show the present-but-unequal comparison distinctly:\n%s", full)
	}
}

// The zero value of Disclosure is Minimal, so a caller who forgets to pick a level fails SAFE.
func TestDisclosureZeroValueFailsSafe(t *testing.T) {
	d := Decide(mainSnap(t), Query{Grants: []Grant{{"*", "", Allow}, {"write", "obj9", Deny}}, Need: "write", Scope: "obj9"})
	var unset Disclosure
	if d.Disclose(unset) != d.Disclose(Minimal) {
		t.Error("zero-value Disclosure must default to Minimal (fail safe)")
	}
	if d.Disclose(unset) == d.Disclose(Full) {
		t.Error("zero-value Disclosure must not default to Full")
	}
}

// Rendering at either disclosure level is a pure read: it does not change the decision, and
// the verdict is identical regardless of which level (or none) is rendered.
func TestDisclosureDoesNotChangeDecision(t *testing.T) {
	snap := mainSnap(t)
	q := Query{Grants: []Grant{{"*", "", Allow}, {"write", "obj9", Deny}}, Need: "write", Scope: "obj9"}

	d := Decide(snap, q)
	allowBefore := d.Allow

	_ = d.Disclose(Full)
	_ = d.Disclose(Minimal)
	_ = d.Disclose(Full)

	if d.Allow != allowBefore {
		t.Error("disclosing must not change the verdict")
	}
	// A freshly computed decision for the same inputs agrees — rendering has no side effects.
	if Decide(snap, q).Allow != allowBefore {
		t.Error("re-deciding the same inputs must yield the same verdict")
	}
}
