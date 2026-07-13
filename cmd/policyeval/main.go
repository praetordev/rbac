// The package doc — the integrator-facing overview and decision surface — lives in doc.go.
// Implementation note: each rule's condition is a small CONDITION TREE with exactly four
// node types (attr, literal, cmp, bool) instead of a hand-written Go predicate. A rule
// matches when SOME grant the subject holds satisfies the tree, so the tree describes the
// shape of a satisfying grant and the matcher supplies the existential over grants.
package main

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
)

// ---- Generic primitives --------------------------------------------------------

// Grant is one thing a subject holds: an opaque capability token at an opaque scope.
// Scope "" means global (applies at every scope). Nothing here knows what either
// string MEANS — they are supplied as data.
type Grant struct {
	Capability string // opaque capability token; "*" is a wildcard
	Scope      string // opaque scope id; "" == global
	Effect     Effect // Allow: a granted capability. Deny: an explicit denial.
}

// Query is the authorization question: holding these grants, does the subject have
// `need` at `scope`? Both need and scope are opaque.
type Query struct {
	Grants []Grant
	Need   string
	Scope  string // "" == a global check
}

// ---- Condition tree (attr / literal / cmp / bool) ------------------------------

type Kind int

const (
	KindAttr    Kind = iota // leaf: a named attribute of the eval context (a string)
	KindLiteral             // leaf: a constant string
	KindCmp                 // compares two value nodes -> bool ("==", "!=")
	KindBool                // combines bool nodes -> bool ("and", "or", "not")
)

// Node is one node of a condition tree. attr/literal produce a string value; cmp/bool
// produce a boolean. cmp's operands are value nodes; bool's operands are bool nodes.
type Node struct {
	Kind        Kind
	Attr        string  // KindAttr
	Literal     string  // KindLiteral
	Op          string  // KindCmp: "=="/"!="   KindBool: "and"/"or"/"not"
	Left, Right *Node   // KindCmp operands
	Kids        []*Node // KindBool operands
}

func attr(name string) *Node  { return &Node{Kind: KindAttr, Attr: name} }
func lit(v string) *Node      { return &Node{Kind: KindLiteral, Literal: v} }
func eq(l, r *Node) *Node     { return &Node{Kind: KindCmp, Op: "==", Left: l, Right: r} }
func ne(l, r *Node) *Node     { return &Node{Kind: KindCmp, Op: "!=", Left: l, Right: r} }
func and(kids ...*Node) *Node { return &Node{Kind: KindBool, Op: "and", Kids: kids} }
func or(kids ...*Node) *Node  { return &Node{Kind: KindBool, Op: "or", Kids: kids} }
func not(k *Node) *Node       { return &Node{Kind: KindBool, Op: "not", Kids: []*Node{k}} }

// env is the evaluation context: the query plus one candidate grant.
type env struct {
	q Query
	g Grant
}

// lookup resolves a named attribute, returning its value and whether the attribute is
// PRESENT. Absence (present == false) is first-class: it is distinct from an attribute
// that is present but holds the empty string (e.g. a global scope ""). Attributes are the
// ONLY place any structure is exposed to the tree; everything else is opaque strings.
func (e env) lookup(name string) (value string, present bool) {
	switch name {
	case "need":
		return e.q.Need, true
	case "scope":
		return e.q.Scope, true
	case "grant.cap":
		return e.g.Capability, true
	case "grant.scope":
		return e.g.Scope, true
	case "grant.effect":
		return e.g.Effect.token(), true
	default:
		return "", false // absent: the policy referenced an attribute this engine does not expose
	}
}

// applyCmp is the single comparison primitive shared by the decision path (evalBool) and
// the trace path (traceCond), so the two can never disagree on a comparison's result.
func applyCmp(op, l, r string) bool {
	switch op {
	case "==":
		return l == r
	case "!=":
		return l != r
	}
	panic("condition: unknown comparison " + op)
}

// tri is a three-valued (Kleene) truth value. An absent attribute makes a comparison
// triUnknown — never triTrue — so absence never coerces to "" and never causes a match,
// directly or through negation. A rule matches only when its condition is triTrue.
type tri int8

const (
	triFalse tri = iota
	triTrue
	triUnknown
)

func triOf(b bool) tri {
	if b {
		return triTrue
	}
	return triFalse
}

// evalValue resolves a value node to its string value and whether it is PRESENT. Literals
// are always present; an attribute is absent when the engine does not expose it.
func evalValue(n *Node, e env) (value string, present bool) {
	switch n.Kind {
	case KindAttr:
		return e.lookup(n.Attr)
	case KindLiteral:
		return n.Literal, true
	default:
		panic("condition: expected a value node (attr/literal)")
	}
}

// evalTri evaluates a condition under three-valued logic. The absent-handling rule, applied
// uniformly to every operator:
//   - Comparison (==, !=): if EITHER operand is absent, the result is triUnknown — an absent
//     value is not comparable and can never be equal or unequal to anything, so it is never a
//     match. It is never read as "".
//   - and: triFalse if any branch is false; else triUnknown if any is unknown; else triTrue.
//   - or:  triTrue if any branch is true; else triUnknown if any is unknown; else triFalse.
//   - not: not(unknown) = unknown — a negated absent comparison stays a non-match (this
//     closes the negation trap: absence can never flip into a match via not).
//
// A grant satisfies the condition only when evalTri == triTrue (see matches); triUnknown and
// triFalse are both non-matches.
func evalTri(n *Node, e env) tri {
	switch n.Kind {
	case KindCmp:
		lv, lp := evalValue(n.Left, e)
		rv, rp := evalValue(n.Right, e)
		if !lp || !rp {
			return triUnknown
		}
		return triOf(applyCmp(n.Op, lv, rv))
	case KindBool:
		switch n.Op {
		case "and":
			r := triTrue
			for _, k := range n.Kids {
				switch evalTri(k, e) {
				case triFalse:
					return triFalse // false dominates
				case triUnknown:
					r = triUnknown
				}
			}
			return r
		case "or":
			r := triFalse
			for _, k := range n.Kids {
				switch evalTri(k, e) {
				case triTrue:
					return triTrue // true dominates
				case triUnknown:
					r = triUnknown
				}
			}
			return r
		case "not":
			switch evalTri(n.Kids[0], e) {
			case triTrue:
				return triFalse
			case triFalse:
				return triTrue
			default:
				return triUnknown
			}
		}
	}
	panic("condition: expected a bool node (cmp/bool)")
}

// evalBool is the boolean view of the decision path: a condition holds only when it is
// definitely true. Absent/unknown is a non-match.
func evalBool(n *Node, e env) bool { return evalTri(n, e) == triTrue }

// matches supplies the existential over grants: a rule condition holds when SOME grant
// satisfies the tree. (A query with no grants matches nothing — default-deny.)
func matches(cond *Node, q Query) bool {
	for _, g := range q.Grants {
		if evalBool(cond, env{q: q, g: g}) {
			return true
		}
	}
	return false
}

// ---- Rules ---------------------------------------------------------------------

type Effect int

const (
	Allow Effect = iota
	Deny
)

func (e Effect) String() string {
	if e == Deny {
		return "DENY"
	}
	return "ALLOW"
}

// token is the lowercase form used as the "grant.effect" attribute value.
func (e Effect) token() string {
	if e == Deny {
		return "deny"
	}
	return "allow"
}

// Rule is a named condition tree with an effect. Cond describes the shape of a grant
// that satisfies the rule; matches() checks whether the subject holds such a grant.
//
// ID is a stable, collision-free identifier assigned at parse time (the rule's position in
// the policy). Names come from policy authors and can collide; ID cannot, so "which rule
// decided" is answered by ID, never by Name.
type Rule struct {
	ID     int
	Name   string
	Effect Effect
	Cond   *Node
}

// RuleRef identifies a rule unambiguously by its stable ID, carrying Name/Effect for
// display. It is what a Decision reports as its decider.
type RuleRef struct {
	ID     int
	Name   string
	Effect Effect
}

func refOf(r Rule) RuleRef { return RuleRef{ID: r.ID, Name: r.Name, Effect: r.Effect} }

// ---- Policy format + parser (JSON text -> rules -> condition trees) -------------

//go:embed policy.json
var policyJSON []byte

// Parser bounds. A policy is untrusted input by contract (its integrity is a perimeter
// concern, see TRUST-BOUNDARY.md), but a *technically valid* policy must still not be able
// to exhaust resources at parse time. These limits close that denial-of-service surface —
// the ONE piece of input-distrust that belongs in the engine, and only because it guards
// the engine's own liveness, not the meaning of any input.
const (
	maxPolicyBytes = 1 << 20 // reject documents larger than 1 MiB before parsing
	maxRules       = 1024    // reject policies with more rules than this
	maxDepth       = 64      // reject condition trees nested deeper than this
	maxNodes       = 10000   // reject policies with more condition nodes than this (total)
	maxLiteralLen  = 4096    // reject string literals longer than this

	// maxBundleBytes caps the raw fetched artifact at INGEST — before it is hashed, verified,
	// extracted, or parsed — so an oversized source cannot force a large allocation ahead of
	// the parser's own len check. It equals maxPolicyBytes because the raw artifact currently
	// IS the policy (Bundle.Raw); a signed-envelope source would raise it by the envelope
	// overhead. See the loader.
	maxBundleBytes = maxPolicyBytes
)

// parseBudget tracks resource consumption across a single policy parse so that width
// (node count) is bounded even when depth is not exceeded.
type parseBudget struct {
	nodes int
}

// rawRule is the on-the-wire shape of one rule; When stays raw for recursive parsing.
type rawRule struct {
	Name   string          `json:"name"`
	Effect string          `json:"effect"`
	When   json.RawMessage `json:"when"`
}

// parsePolicy parses a JSON policy document into ordered rules. A rule is
// {name, effect: "allow"|"deny", when: <condition>}. A condition is a single-key object
// whose key names the node type:
//
//	{"attr": "<name>"}             reference a context attribute (a value node)
//	{"lit":  "<string>"}          a constant string        (a value node)
//	{"eq":  [<value>, <value>]}   / {"ne": [...]}   compare two value nodes
//	{"all": [<cond>, ...]}        / {"any": [...]}  conjoin / disjoin conditions
//	{"not":  <cond>}              negate a condition
func parsePolicy(data []byte) ([]Rule, error) {
	if len(data) > maxPolicyBytes {
		return nil, fmt.Errorf("policy is %d bytes, exceeds maximum of %d", len(data), maxPolicyBytes)
	}
	var raws []rawRule
	if err := json.Unmarshal(data, &raws); err != nil {
		return nil, fmt.Errorf("policy must be a JSON array of rules: %w", err)
	}
	if len(raws) > maxRules {
		return nil, fmt.Errorf("policy has %d rules, exceeds maximum of %d", len(raws), maxRules)
	}
	budget := &parseBudget{}
	out := make([]Rule, len(raws))
	for i, rr := range raws {
		if rr.Name == "" {
			return nil, fmt.Errorf("rule %d: missing name", i)
		}
		eff, err := parseEffect(rr.Effect)
		if err != nil {
			return nil, fmt.Errorf("rule %q: %w", rr.Name, err)
		}
		cond, err := parseNode(rr.When, 1, budget)
		if err != nil {
			return nil, fmt.Errorf("rule %q: %w", rr.Name, err)
		}
		out[i] = Rule{ID: i, Name: rr.Name, Effect: eff, Cond: cond}
	}
	return out, nil
}

func parseEffect(s string) (Effect, error) {
	switch s {
	case "allow":
		return Allow, nil
	case "deny":
		return Deny, nil
	default:
		return 0, fmt.Errorf("effect must be \"allow\" or \"deny\", got %q", s)
	}
}

// parseNode parses one condition node — a single-key object whose key names the node type.
// depth is this node's nesting level (root conditions start at 1); budget bounds the total
// number of nodes across the whole policy. Both guard against pathological but valid input.
func parseNode(raw json.RawMessage, depth int, budget *parseBudget) (*Node, error) {
	if depth > maxDepth {
		return nil, fmt.Errorf("condition nesting exceeds maximum depth of %d", maxDepth)
	}
	budget.nodes++
	if budget.nodes > maxNodes {
		return nil, fmt.Errorf("policy exceeds maximum of %d condition nodes", maxNodes)
	}

	var obj map[string]json.RawMessage
	if err := json.Unmarshal(raw, &obj); err != nil {
		return nil, fmt.Errorf("condition must be an object: %w", err)
	}
	// Zero and multiple keys are distinct authoring mistakes; report them distinctly rather
	// than silently dispatching on whichever key map iteration happens to yield first.
	switch {
	case len(obj) == 0:
		return nil, fmt.Errorf("condition object has no keys; expected exactly one node type")
	case len(obj) > 1:
		return nil, fmt.Errorf("condition object has %d keys (%s); expected exactly one node type", len(obj), joinKeys(obj))
	}

	for key, val := range obj {
		switch key {
		case "attr":
			s, err := parseString(val)
			if err != nil {
				return nil, fmt.Errorf("attr: %w", err)
			}
			if len(s) > maxLiteralLen {
				return nil, fmt.Errorf("attr name is %d bytes, exceeds maximum of %d", len(s), maxLiteralLen)
			}
			return attr(s), nil
		case "lit":
			s, err := parseString(val)
			if err != nil {
				return nil, fmt.Errorf("lit: %w", err)
			}
			if len(s) > maxLiteralLen {
				return nil, fmt.Errorf("lit is %d bytes, exceeds maximum of %d", len(s), maxLiteralLen)
			}
			return lit(s), nil
		case "eq", "ne":
			ops, err := parseNodeList(val, depth+1, budget)
			if err != nil {
				return nil, fmt.Errorf("%s: %w", key, err)
			}
			if len(ops) != 2 {
				return nil, fmt.Errorf("%s needs exactly 2 operands, got %d", key, len(ops))
			}
			if key == "eq" {
				return eq(ops[0], ops[1]), nil
			}
			return ne(ops[0], ops[1]), nil
		case "all", "any":
			ops, err := parseNodeList(val, depth+1, budget)
			if err != nil {
				return nil, fmt.Errorf("%s: %w", key, err)
			}
			if len(ops) == 0 {
				return nil, fmt.Errorf("%s needs at least one operand", key)
			}
			if key == "all" {
				return and(ops...), nil
			}
			return or(ops...), nil
		case "not":
			child, err := parseNode(val, depth+1, budget)
			if err != nil {
				return nil, fmt.Errorf("not: %w", err)
			}
			return not(child), nil
		default:
			return nil, fmt.Errorf("unknown condition %q", key)
		}
	}
	return nil, fmt.Errorf("empty condition")
}

// joinKeys returns the keys of a condition object, sorted, for a deterministic error message.
func joinKeys(obj map[string]json.RawMessage) string {
	keys := make([]string, 0, len(obj))
	for k := range obj {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return strings.Join(keys, ", ")
}

func parseNodeList(raw json.RawMessage, depth int, budget *parseBudget) ([]*Node, error) {
	var arr []json.RawMessage
	if err := json.Unmarshal(raw, &arr); err != nil {
		return nil, fmt.Errorf("expected an array of conditions: %w", err)
	}
	nodes := make([]*Node, len(arr))
	for i, r := range arr {
		n, err := parseNode(r, depth, budget)
		if err != nil {
			return nil, fmt.Errorf("operand %d: %w", i, err)
		}
		nodes[i] = n
	}
	return nodes, nil
}

func parseString(raw json.RawMessage) (string, error) {
	var s string
	if err := json.Unmarshal(raw, &s); err != nil {
		return "", fmt.Errorf("expected a string: %w", err)
	}
	return s, nil
}

// ---- The fold ------------------------------------------------------------------

// Decision is the accumulator threaded through the fold.
type Decision struct {
	Allow    bool
	Reason   string
	Snapshot string      // id of the snapshot that produced this decision (stamped outside the fold)
	locked   bool        // once true, later rules can no longer change the verdict
	decider  RuleRef     // the rule that set the current verdict (valid iff decided)
	decided  bool        // whether any rule decided (false == default-deny / fail closed)
	trace    []RuleTrace // structured, canonical record of every fold step (see trace.go)
}

// Decider reports the rule that determined this decision, by stable ID, and true — or a
// zero RuleRef and false when no rule decided (default-deny or fail-closed). This is the
// public "who decided and how" surface; callers should key on RuleRef.ID, never on Name.
func (d Decision) Decider() (RuleRef, bool) { return d.decider, d.decided }

// reasonFor derives the human Reason from the decider in ONE place, so deny-overrides,
// first-match, and default-deny all render the same event the same way (no more "allowed
// by" vs "ALLOW by" divergence).
func reasonFor(ref RuleRef, decided bool) string {
	if !decided {
		return "default-deny (no rule matched)"
	}
	verb := "allowed"
	if ref.Effect == Deny {
		verb = "denied"
	}
	return verb + " by " + ref.Name
}

// Strategy is one fold step: combine the running decision with the next rule. It returns
// the updated decision and the rule's OUTCOME classification for the trace. The strategy
// decides the verdict only; it builds no prose — rendering lives entirely in trace.go.
type Strategy func(acc Decision, r Rule, matched bool) (Decision, RuleOutcome)

// evaluate folds the rules into a decision under the given strategy, from default-deny,
// building the structured trace as it goes. The verdict logic is identical to the
// trace-off path (evalVerdict); the only extra work is recording each rule's match
// attempts and outcome, which never feeds back into the verdict.
func evaluate(rules []Rule, q Query, combine Strategy) Decision {
	acc := Decision{Allow: false}
	for _, r := range rules {
		matched, attempts := traceMatch(r.Cond, q)
		before := acc.locked
		var outcome RuleOutcome
		acc, outcome = combine(acc, r, matched)
		acc.trace = append(acc.trace, RuleTrace{
			ID:       r.ID,
			Name:     r.Name,
			Effect:   r.Effect,
			Outcome:  outcome,
			Decisive: acc.locked && !before, // this rule is the one that locked the verdict
			Attempts: attempts,
		})
	}
	acc.Reason = reasonFor(acc.decider, acc.decided)
	return acc
}

// evalVerdict is the TRACE-OFF path: the same fold, computing only the verdict with the
// pure matcher and building no trace. It exists to prove that tracing has no effect on the
// decision — evaluate(...).Allow/Reason/Decider must equal evalVerdict(...)'s.
func evalVerdict(rules []Rule, q Query, combine Strategy) Decision {
	acc := Decision{Allow: false}
	for _, r := range rules {
		acc, _ = combine(acc, r, matches(r.Cond, q))
	}
	acc.Reason = reasonFor(acc.decider, acc.decided)
	return acc
}

// denyOverrides: any matching Deny is final and wins; a matching Allow sets the verdict
// but a later Deny can still override it. Absent any match, default-deny stands. The
// deciding rule is recorded as the verdict is set; Reason is derived later, in one place.
func denyOverrides(acc Decision, r Rule, matched bool) (Decision, RuleOutcome) {
	switch {
	case acc.locked:
		return acc, OutcomeSkipped
	case !matched:
		return acc, OutcomeNoMatch
	case r.Effect == Deny:
		acc.Allow, acc.locked = false, true
		acc.decider, acc.decided = refOf(r), true
		return acc, OutcomeDeny
	default: // Allow — provisional; a later matching allow overwrites, a later deny overrides
		acc.Allow = true
		acc.decider, acc.decided = refOf(r), true
		return acc, OutcomeAllow
	}
}

// firstMatch: the first matching rule decides, full stop.
func firstMatch(acc Decision, r Rule, matched bool) (Decision, RuleOutcome) {
	switch {
	case acc.locked:
		return acc, OutcomeSkipped
	case !matched:
		return acc, OutcomeNoMatch
	default:
		acc.Allow = r.Effect == Allow
		acc.locked = true
		acc.decider, acc.decided = refOf(r), true
		if r.Effect == Deny {
			return acc, OutcomeDeny
		}
		return acc, OutcomeAllow
	}
}

// ---- Driver --------------------------------------------------------------------

func main() {
	rules, err := parsePolicy(policyJSON)
	if err != nil {
		fmt.Fprintln(os.Stderr, "policy error:", err)
		os.Exit(1)
	}
	fmt.Printf("loaded %d rules from policy.json\n\n", len(rules))

	cases := []struct {
		desc string
		q    Query
	}{
		{
			"global grant of the exact capability",
			Query{Grants: []Grant{{"read", "", Allow}}, Need: "read", Scope: "obj1"},
		},
		{
			"scoped grant, matching scope",
			Query{Grants: []Grant{{"read", "obj1", Allow}}, Need: "read", Scope: "obj1"},
		},
		{
			"scoped grant, DIFFERENT scope",
			Query{Grants: []Grant{{"read", "obj1", Allow}}, Need: "read", Scope: "obj2"},
		},
		{
			"global wildcard",
			Query{Grants: []Grant{{"*", "", Allow}}, Need: "write", Scope: "obj5"},
		},
		{
			"scoped wildcard on the scope",
			Query{Grants: []Grant{{"*", "obj3", Allow}}, Need: "read", Scope: "obj3"},
		},
		{
			"global wildcard + explicit scoped deny",
			Query{Grants: []Grant{{"*", "", Allow}, {"write", "obj9", Deny}}, Need: "write", Scope: "obj9"},
		},
		{
			"no grants",
			Query{Grants: nil, Need: "read", Scope: "obj1"},
		},
	}

	for _, tc := range cases {
		fmt.Printf("● %s\n  %s\n", tc.desc, describe(tc.q))
		printResult("deny-overrides", evaluate(rules, tc.q, denyOverrides))
		printResult("first-match", evaluate(rules, tc.q, firstMatch))
		fmt.Println()
	}

	demoSnapshots()
	demoDisclosure()
	demoLoader()
}

func describe(q Query) string {
	held := make([]string, len(q.Grants))
	for i, g := range q.Grants {
		scope := g.Scope
		if scope == "" {
			scope = "*global*"
		}
		held[i] = g.Effect.token() + " " + g.Capability + "@" + scope
	}
	scope := q.Scope
	if scope == "" {
		scope = "*global*"
	}
	return fmt.Sprintf("holds {%s}; need %q @ %s", strings.Join(held, ", "), q.Need, scope)
}

func printResult(strategy string, d Decision) {
	fmt.Printf("  [%s]\n", strategy)
	for _, line := range strings.Split(d.Explain(), "\n") {
		fmt.Printf("    %s\n", line)
	}
}
