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
// # Trust
//
// The engine trusts every [Grant] in Query.Grants EQUALLY and cannot detect a forged one;
// their provenance is your responsibility. Resolve grants from a store keyed by a verified
// identity — never from request-controlled input such as the request body, query string,
// headers, or cookies. The full per-grant trust obligations accompany the trust-contract
// documentation.
//
// # Examples
//
// See the runnable [ExampleDecide] for the smallest correct call end to end.
package main
