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
// # What the model cannot express (the genericness boundary)
//
// The engine is generic over VALUES and STRUCTURE — any opaque tokens, any condition-tree
// shape — but its matching VOCABULARY is CLOSED: a capability-grant model, not open-attribute
// ABAC. Its only comparison is string EQUALITY (eq / ne). Check this list BEFORE designing a
// policy; if a rule needs any of the following, it cannot be expressed here:
//
//   - Ordering or ranges. There is no <, >, <=, >=. You cannot match "level at least 3", a
//     price ceiling, or any threshold — values are compared only for exact equality.
//   - Numbers or time. Values are opaque strings; "10" and "9" are unequal strings, never
//     compared as numbers. No time-of-day window, no expiry-before-now, no counting or rates.
//   - Patterns. No prefix, suffix, substring, glob, or regular expression — only exact match.
//     Even "*" is NOT a wildcard: it is the literal string "*", matching only where a policy
//     opts in with eq(grant.cap, "*"). See [Example_genericnessBoundary].
//   - Arbitrary or context attributes. Only the five closed names resolve (need, scope,
//     grant.cap, grant.scope, grant.effect). Request time, source address, resource owner,
//     environment, or any subject.* attribute is ABSENT — a non-match, never a match.
//   - Cross-grant conditions. A rule's condition is evaluated against ONE candidate grant at a
//     time (the match is existential over Query.Grants), so a single rule cannot require the
//     subject to hold two DIFFERENT grants at once.
//
// These limits are deliberate. Generalizing to an open-attribute (ABAC) model — arbitrary
// attributes and relational operators — is a separate, parked fork, out of scope for this
// engine. Design within the closed vocabulary, or choose a different tool; do not assume the
// missing pieces are there.
//
// # Flattening hierarchies (your responsibility)
//
// The engine is shape-agnostic: scopes and capabilities are opaque strings compared by exact
// equality, with no notion of hierarchy, containment, prefix, or inheritance. A grant at
// "squadron-1" does NOT cover "squadron-1/ship-9"; a grant at an org does not cascade to its
// teams. Any tree — org -> dept -> team, a resource path, a group's inherited capabilities —
// must be FLATTENED by the consumer into namespaced scopes (or attributes) BEFORE the call.
//
// You choose the containment convention, because only you know it. Two common shapes:
//
//   - Enumerate: expand a broad authority into one grant per covered leaf (a command over
//     squadron-1 becomes grants for squadron-1/ship-9, squadron-1/ship-10, ...).
//   - Namespace: encode the path in the scope string (squadron-1/ship-9) and issue/request the
//     fully-qualified scope, so exact equality does the matching.
//
// Either way, the hierarchy is resolved on YOUR side of the boundary; the engine only ever
// compares the already-flattened strings. See the runnable [Example_flattening].
//
// # Missing attributes (absent is a non-match)
//
// When a policy names an attribute the engine does not expose — anything outside the five
// closed names — that attribute is ABSENT. Absence is first-class and uses three-valued
// (Kleene) logic: an absent operand makes its comparison UNKNOWN, never true. A rule matches
// only when its condition is definitely true, so:
//
//   - Absent is a non-match against EVERY value, including the empty string. attr == "" is
//     true only when the attribute is PRESENT and empty (e.g. a global scope ""), never when
//     it is absent. Absent and present-empty differ in the VERDICT, not just the trace.
//   - not() of an absent comparison stays unknown — negation can never turn absence into a
//     match. There is no way to open access by referencing a missing attribute.
//   - all() fails if any branch is definitely false; any() still succeeds if another branch is
//     definitely true. A missing attribute closes an all(), but an any()-branch can tolerate it.
//
// The upshot: missing data never grants access; it only ever withholds it. See the runnable
// [Example_absentVsEmpty].
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
// # Fail-closed degradation
//
// Every failure mode denies rather than opens:
//
//   - No snapshot installed -> deny. Decide against a nil snapshot returns deny; it never
//     panics and never opens.
//   - A malformed, oversized, or pathologically nested bundle is REJECTED at parse time and
//     the previously installed (last known-good) snapshot stays in place untouched. A bad load
//     never becomes current, never clears the policy, and never opens access.
//   - A source fetch that fails or exceeds the size bound leaves the last known-good snapshot
//     serving (the loader treats it as a refresh failure).
//
// The safe-degradation guarantee: given trusted inputs the engine is total and deterministic,
// and under any policy-plumbing failure it withholds access rather than granting it. See the
// runnable [Example_failClosed].
//
// # Disclosing a decision (logs vs caller)
//
// A [Decision] carries a full structured trace so a policy author can self-diagnose a denial —
// but that same detail would let a caller probe and reverse-engineer the ruleset. Choose the
// audience explicitly with [Decision.Disclose]:
//
//   - Disclose(Full) -> your OWN logs. The complete rationale: which rules matched or were
//     skipped, the deciding rule, per-node comparison results, absent-vs-unequal, and the
//     snapshot id.
//   - Disclose(Minimal) -> the caller. A constant per verdict ("access permitted" /
//     "access denied") that names no rule, attribute, or snapshot, so no two permits — or two
//     denials — are distinguishable from it.
//
// The zero value of the level is Minimal, so forgetting to choose one fails SAFE (reveals the
// least). The engine adds no identifier of its own; to correlate a caller-facing denial with
// its full logged trace, log Disclose(Full) alongside YOUR request id. Never send Full to the
// caller — it leaks the ruleset. See the runnable [Example_disclosure].
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
// # The attribute source seam (yours to build)
//
// The engine deliberately ships NO attribute resolver — nothing that turns a principal into
// its grants. That step is app-specific by nature (your identity system, your grant store),
// so shipping one would be guessing, and a wrong default here is a security bug. The seam is
// left open ON PURPOSE; what is specified is the CONTRACT it must satisfy, not an
// implementation.
//
// Your resolver sits between a verified identity and the Query. Conceptually:
//
//	resolve(verifiedIdentity) -> []Grant   // from a store only the app writes
//
// It MUST satisfy the provenance obligations above: the identity comes from a verified
// source, the grants from a store the caller cannot influence, and nothing on the request
// path may add to or edit the result. The engine consumes whatever []Grant you supply as
// Query.Grants and asks no questions about where it came from — which is exactly why the
// contract is yours, not the engine's.
//
// There is no reference resolver to copy, by design. [Example_enforcement] and
// [Example_attributeProvenance] show the consuming side: a trusted lookup keyed by identity.
//
// # Examples
//
// Runnable, verified end to end:
//   - [ExampleDecide] — the smallest correct call.
//   - [Example_authoring] — the full condition vocabulary and deny-overrides in one bundle.
//   - [Example_enforcement] — a PEP at the resource boundary, refusing on deny.
//   - [Example_attributeProvenance] — forged vs trusted grants; the engine cannot tell.
//   - [Example_genericnessBoundary] — "*" is not a wildcard; the engine only compares equal.
//   - [Example_absentVsEmpty] — an absent attribute is a non-match, even against "".
//   - [Example_failClosed] — no snapshot and a bad load both deny; last known-good is kept.
//   - [Example_disclosure] — Minimal hides structure from the caller; Full is for your logs.
//   - [Example_flattening] — a hierarchy flattened into namespaced scopes; no prefix logic.
package main
