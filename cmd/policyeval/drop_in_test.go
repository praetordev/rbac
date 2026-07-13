package main

import (
	"strings"
	"testing"
)

// TestDropIn_ForeignVocabulary is the epic close-out capstone: a wholly foreign policy world,
// authored as if by a stranger in a different industry, run through the SAME engine unchanged
// (parse -> snapshot -> evaluate -> trace). It is a standing regression guard against
// structural genericness leaks that grep cannot catch.
//
// The foreign world is a content-moderation / publishing pipeline. It is structurally distinct
// from the capability fixtures, not a relabel:
//   - a different action vocabulary: publish / retract / escalate (vs read / write);
//   - a different scope convention: channel-* identifiers (vs objN);
//   - it leans on FIRST-MATCH priority ordering (the capability demo/pivotal lean deny-overrides);
//   - it uses `not`, which NO primary policy fixture (policy.json, v1, v2) exercises;
//   - it references a foreign attribute, `clearance`, that the engine has never heard of.
//
// GENERICNESS BOUNDARY (reported, not forced green): the engine's attribute vocabulary is
// closed to {need, scope, grant.cap, grant.scope, grant.effect} (env.lookup). A foreign
// *matching* resource/context attribute (a real `clearance`, a `time` of day) is therefore NOT
// expressible — it resolves as ABSENT. So the foreign world can vary every value, its whole
// structure, and its strategy and run unchanged, but a new matching attribute would require an
// engine change, which this capstone does NOT make. The foreign attribute below is exercised
// as the required absent-attribute case.
const foreignPolicy = `[
  {
    "name": "quarantine-block",
    "effect": "deny",
    "when": { "all": [
      { "eq": [ { "attr": "grant.effect" }, { "lit": "deny" } ] },
      { "eq": [ { "attr": "grant.cap" }, { "attr": "need" } ] },
      { "eq": [ { "attr": "grant.scope" }, { "attr": "scope" } ] }
    ] }
  },
  {
    "name": "clearance-gate",
    "effect": "allow",
    "when": { "eq": [ { "attr": "clearance" }, { "lit": "granted" } ] }
  },
  {
    "name": "open-channel-action",
    "effect": "allow",
    "when": { "all": [
      { "eq": [ { "attr": "grant.effect" }, { "lit": "allow" } ] },
      { "eq": [ { "attr": "grant.cap" }, { "attr": "need" } ] },
      { "eq": [ { "attr": "grant.scope" }, { "attr": "scope" } ] },
      { "not": { "eq": [ { "attr": "scope" }, { "lit": "channel-embargo" } ] } }
    ] }
  }
]`

func TestDropIn_ForeignVocabulary(t *testing.T) {
	// Full path: parse + freeze into a snapshot that leans on first-match, then Decide.
	snap := mustSnap(t, "moderation-v1", []byte(foreignPolicy), firstMatch)

	cases := []struct {
		name    string
		q       Query
		allow   bool
		decider string // "" = default-deny (no rule decided)
		effect  Effect
	}{
		{
			// open channel, matching allow grant -> permitted by the publish rule.
			"publish on an open channel",
			Query{Grants: []Grant{{"publish", "channel-open", Allow}}, Need: "publish", Scope: "channel-open"},
			true, "open-channel-action", Allow,
		},
		{
			// same, but the embargo channel is excluded by not(scope == channel-embargo).
			"publish on the embargo channel is blocked by not()",
			Query{Grants: []Grant{{"publish", "channel-embargo", Allow}}, Need: "publish", Scope: "channel-embargo"},
			false, "", Allow,
		},
		{
			// holding a deny grant too: first-match takes the highest-priority rule (the deny),
			// NOT deny-overrides — the deny wins by ORDER.
			"a deny grant wins by first-match order",
			Query{Grants: []Grant{{"publish", "channel-open", Deny}, {"publish", "channel-open", Allow}}, Need: "publish", Scope: "channel-open"},
			false, "quarantine-block", Deny,
		},
		{
			// the foreign 'clearance' attribute is absent -> clearance-gate is a non-match, and
			// no other rule matches this action -> default deny. Absent never opens access.
			"absent clearance is a non-match in a domain the engine has never seen",
			Query{Grants: []Grant{{"publish", "channel-open", Allow}}, Need: "escalate", Scope: "channel-open"},
			false, "", Allow,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			d := Decide(snap, tc.q)
			if d.Allow != tc.allow {
				t.Errorf("allow = %v, want %v", d.Allow, tc.allow)
			}
			ref, ok := d.Decider()
			if tc.decider == "" {
				if ok {
					t.Errorf("expected no decider (default-deny), got %q", ref.Name)
				}
				return
			}
			if !ok || ref.Name != tc.decider || ref.Effect != tc.effect {
				t.Errorf("decider = %+v (ok=%v), want %q/%v", ref, ok, tc.decider, tc.effect)
			}
			// The stable RuleRef ID must resolve back to the deciding rule in the snapshot.
			if ref.ID < 0 || ref.ID >= len(snap.rules) || snap.rules[ref.ID].Name != ref.Name {
				t.Errorf("decider ID %d does not resolve to rule %q in the snapshot", ref.ID, ref.Name)
			}
		})
	}

	// The required absent-attribute confirmation, at the trace level: the foreign attribute
	// renders distinctly as <absent>, proving absent-is-non-match holds in a foreign domain.
	d := Decide(snap, Query{Grants: []Grant{{"publish", "channel-open", Allow}}, Need: "escalate", Scope: "channel-open"})
	if d.Allow {
		t.Fatal("absent clearance must not open access in the foreign world")
	}
	if full := d.Disclose(Full); !strings.Contains(full, "clearance=<absent>") {
		t.Errorf("full trace must render the foreign absent attribute distinctly:\n%s", full)
	}
}
