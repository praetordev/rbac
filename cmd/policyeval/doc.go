// Command policyeval is a generic capability-grant authorization engine: a pure Policy
// Decision Point that answers "may this request proceed?" by evaluating opaque capability
// and scope strings against an ordered list of rules.
//
// It is deliberately GENERIC. It knows nothing about organizations, ownership, tenants, or
// any named role. The only concepts are opaque capability tokens and opaque scope ids — the
// engine treats them as strings and never interprets them. The consuming app's vocabulary
// lives entirely in the data, not here.
//
// The binary is runnable (go run ./cmd/policyeval) and prints a demonstration; the types
// documented below are the surface an integrator programs against.
//
// # The decision surface
//
// One question type in, one decision out. There are three entry points, all taking the same
// [Query] and returning the same [Decision]:
//
//	Decide(snap *Snapshot, q Query) Decision   // evaluate against a snapshot you already hold
//	(*Holder).Decide(q Query) Decision         // evaluate against a Holder's current snapshot
//	(*Loader).Decide(q Query) Decision         // evaluate against a Loader's current snapshot
//
// Pick [Decide] when you hold a [Snapshot] directly, [Holder.Decide] when a [Holder] owns the
// current snapshot, or [Loader.Decide] when a [Loader] fetches and swaps snapshots for you.
// All three evaluate identically; they differ only in where the current snapshot comes from.
//
// The [Query] is the authorization question:
//
//	type Query struct {
//		Grants []Grant // the grants the subject holds (see "Trust")
//		Need   string  // the capability being requested; opaque
//		Scope  string  // the scope it is requested at; "" means a global check
//	}
//
//	type Grant struct {
//		Capability string // opaque capability token; "*" is a wildcard
//		Scope      string // opaque scope id; "" == global
//		Effect     Effect // Allow (a granted capability) or Deny (an explicit denial)
//	}
//
// A decision is reached by EXISTENTIAL match: a rule matches when SOME [Grant] in
// Query.Grants satisfies its condition, and a combining strategy folds the matching rules
// into the final verdict. Two strategies ship: denyOverrides (any matching Deny wins) and
// firstMatch (the first matching rule decides).
//
// # Reading a decision
//
// A [Decision] is the verdict plus a structured account of how it was reached:
//
//	type Decision struct {
//		Allow    bool   // the verdict
//		Reason   string // a human reason (prefer Disclose, below)
//		Snapshot string // id of the snapshot that produced this decision
//		// unexported fields carry the structured trace
//	}
//
// Read [Decision.Allow] for the verdict. For "which rule decided, and how", use
// [Decision.Decider], which reports the deciding rule by its stable ID:
//
//	type RuleRef struct { ID int; Name string; Effect Effect }
//	func (d Decision) Decider() (RuleRef, bool)
//
// Decider returns (ref, true) naming the rule that set the verdict, or (zero, false) when no
// rule decided — a default-deny / fail-closed outcome. Key on RuleRef.ID, never on Name:
// names come from policy authors and can collide; ID cannot.
//
// For the rationale surface — a minimal reason safe for the requester versus a full trace for
// your own logs — see [Decision.Disclose].
//
// # The conceptual-to-actual mapping
//
// Integrators arrive with the universal mental model can(subject, action, resource, context).
// This engine has NO such call, and the four parts do NOT map one-to-one. Read the mapping —
// and its friction — before designing a policy; the friction is where most first integrations
// go wrong:
//
//	conceptual   real input      friction to know up front
//	----------   ----------      --------------------------
//	subject      Query.Grants    There is NO subject/principal field. The subject exists only
//	                             as the grants it holds; you resolve principal -> grants
//	                             BEFORE the call (see "Trust").
//	action       Query.Need      NOT implied by which method you call — every entry point
//	                             takes the same Query; the action is data in Need.
//	resource     Query.Scope     "" means a global check, not "no resource".
//	context      (no input)      There is NO context parameter and no free-form attribute
//	                             bag. A policy may reference only five attribute names —
//	                             need, scope, grant.cap, grant.scope, grant.effect — all
//	                             derived from the Query and the candidate Grant. Every other
//	                             name is absent. If you expected to pass arbitrary context
//	                             attributes, you cannot.
//
// # Authoring a policy bundle
//
// A bundle is a JSON array of rules, parsed once by [NewSnapshot]. Each rule is:
//
//	{ "name": "<label>", "effect": "allow" | "deny", "when": <condition> }
//
// name is a human label (it may collide; the engine identifies rules by position/ID, never
// by name). effect is the verdict the rule casts when it matches. when is a CONDITION TREE
// of exactly these node types, each a single-key JSON object:
//
//	{ "attr": "<name>" }             a value: one of the five attributes (need, scope,
//	                                 grant.cap, grant.scope, grant.effect)
//	{ "lit":  "<string>" }           a value: a constant string
//	{ "eq":  [ <value>, <value> ] }  true iff the two values are equal
//	{ "ne":  [ <value>, <value> ] }  true iff the two values differ
//	{ "all": [ <cond>, ... ] }       AND: true iff every operand is true (>= 1 operand)
//	{ "any": [ <cond>, ... ] }       OR:  true iff some operand is true  (>= 1 operand)
//	{ "not": <cond> }                negation of one operand
//
// A rule MATCHES when SOME grant the subject holds makes its when tree true — the match is
// existential over Query.Grants, and grant.cap/grant.scope/grant.effect refer to the grant
// currently being tried. (A rule therefore matches only if the subject holds at least one
// grant, even when its condition names no grant attribute.) A malformed tree is rejected at
// parse time with a specific error — unknown node type, wrong operand count, an empty
// object, or an over-nested / over-large policy — and a rejected bundle never becomes a
// snapshot.
//
// The combining strategy, chosen at [NewSnapshot] time, folds the rules into one verdict and
// determines how much rule ORDER matters:
//
//	denyOverrides — a matching Deny is a veto: it wins wherever it sits, overriding a
//	                matching Allow. Order barely matters; author broad allows with denies as
//	                carve-outs. Default-deny if nothing matches.
//	firstMatch    — the first matching rule decides, full stop. Here ORDER IS THE POLICY:
//	                put specific exceptions first, general rules last.
//
// See the runnable [Example_authoring].
//
// # Enforcing a decision at the boundary (the PEP)
//
// The engine is a Policy Decision Point; enforcement is yours. Wire a Policy Enforcement
// Point inline at the resource boundary — the one place a request crosses into a protected
// operation — so no request reaches the operation without a permit:
//
//  1. Resolve the subject's grants from a TRUSTED source keyed by a verified identity (see
//     "Trust"), never from request input.
//  2. Build the [Query]: the resolved Grants, the Need (the action), the Scope (the resource).
//  3. [Decide], then ENFORCE — proceed only if Decision.Allow; otherwise refuse.
//  4. Disclose minimally to the caller: [Decision.Disclose](Minimal) is a constant per
//     verdict and leaks no structure. Log Disclose(Full) to your OWN logs for diagnosis.
//
// See the runnable [Example_enforcement].
//
// # Trust — attribute provenance (read this)
//
// This is the load-bearing obligation. The engine trusts every [Grant] in Query.Grants
// EQUALLY and CANNOT detect a forged one: a Grant carries a capability, a scope, and an
// effect, but no origin — provenance is unrepresented by design. Two grants that differ only
// in where they came from are identical to the evaluator, so it honors whatever the Query
// holds. The defense lives entirely at YOUR boundary.
//
// Query.Grants IS the attribute bag. Because a policy can reference only the five closed
// attribute names (need, scope, grant.cap, grant.scope, grant.effect), there is no separate
// subject.* bag to protect — the grants are it. The value whose source you must guarantee is
// Query.Grants, and the obligation is PER-GRANT, PER-FIELD: one forged Grant — or one genuine
// grant with a forged Scope — compromises the decision.
//
// MUST — resolve grants from trust:
//   - the subject's grants from a store only the app writes, looked up BY a verified identity;
//   - the identity itself from a verified source (a validated session or signed assertion).
//
// MUST NOT — build grants from anything the caller controls:
//   - the request body, query string, headers, or cookies;
//   - any grant the client asserts about itself.
//
// The pitfall to guard against is LAUNDERING: unmarshalling client-supplied grants into
// Query.Grants and passing them to Decide — the "grants from the request body" mistake. The
// engine is not fooled; it does exactly its job; but the access is real because the INPUT was
// forged. Query.Need and Query.Scope are typically request-derived — they describe WHAT is
// asked, which is fine — but constrain them so a caller cannot pose a question that is not
// theirs to ask. The load-bearing input remains Query.Grants.
//
// See the runnable [Example_attributeProvenance] for the incorrect-vs-correct contrast.
//
// # Examples
//
// Runnable, verified end to end:
//   - [ExampleDecide] — the smallest correct call.
//   - [Example_authoring] — the full condition vocabulary and deny-overrides in one bundle.
//   - [Example_enforcement] — a PEP at the resource boundary, refusing on deny.
//   - [Example_attributeProvenance] — forged vs trusted grants; the engine cannot tell.
package main
