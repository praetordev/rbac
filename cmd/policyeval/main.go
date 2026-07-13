// Command policyeval explores RBAC evaluation by FOLDING a running decision over an
// in-memory, ordered list of rules. It is deliberately GENERIC: it knows nothing about
// organizations, ownership, tenants, or any named role. The only concepts are opaque
// capability tokens and opaque scope ids — the engine treats them as strings and never
// interprets them. The consumer's vocabulary lives entirely in the data, not here.
//
// Each rule's condition is a small CONDITION TREE with exactly four node types —
// attr, literal, cmp, bool — instead of a hand-written Go predicate. A rule matches
// when SOME grant the subject holds satisfies the tree, so the tree describes the shape
// of a satisfying grant and the matcher supplies the existential over grants. The fold
// itself is unchanged.
//
// Run:  go run ./cmd/policyeval
package main

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"os"
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

func evalString(n *Node, e env) string {
	switch n.Kind {
	case KindAttr:
		v, _ := e.lookup(n.Attr) // decision path treats an absent attribute as "" (unchanged behaviour)
		return v
	case KindLiteral:
		return n.Literal
	default:
		panic("condition: expected a value node (attr/literal)")
	}
}

func evalBool(n *Node, e env) bool {
	switch n.Kind {
	case KindCmp:
		return applyCmp(n.Op, evalString(n.Left, e), evalString(n.Right, e))
	case KindBool:
		switch n.Op {
		case "and":
			for _, k := range n.Kids {
				if !evalBool(k, e) {
					return false
				}
			}
			return true
		case "or":
			for _, k := range n.Kids {
				if evalBool(k, e) {
					return true
				}
			}
			return false
		case "not":
			return !evalBool(n.Kids[0], e)
		}
	}
	panic("condition: expected a bool node (cmp/bool)")
}

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
type Rule struct {
	Name   string
	Effect Effect
	Cond   *Node
}

// ---- Policy format + parser (JSON text -> rules -> condition trees) -------------

//go:embed policy.json
var policyJSON []byte

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
	var raws []rawRule
	if err := json.Unmarshal(data, &raws); err != nil {
		return nil, fmt.Errorf("policy must be a JSON array of rules: %w", err)
	}
	out := make([]Rule, len(raws))
	for i, rr := range raws {
		if rr.Name == "" {
			return nil, fmt.Errorf("rule %d: missing name", i)
		}
		eff, err := parseEffect(rr.Effect)
		if err != nil {
			return nil, fmt.Errorf("rule %q: %w", rr.Name, err)
		}
		cond, err := parseNode(rr.When)
		if err != nil {
			return nil, fmt.Errorf("rule %q: %w", rr.Name, err)
		}
		out[i] = Rule{Name: rr.Name, Effect: eff, Cond: cond}
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
func parseNode(raw json.RawMessage) (*Node, error) {
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(raw, &obj); err != nil {
		return nil, fmt.Errorf("condition must be an object: %w", err)
	}
	if len(obj) != 1 {
		return nil, fmt.Errorf("condition must have exactly one key, got %d", len(obj))
	}
	for key, val := range obj {
		switch key {
		case "attr":
			s, err := parseString(val)
			if err != nil {
				return nil, fmt.Errorf("attr: %w", err)
			}
			return attr(s), nil
		case "lit":
			s, err := parseString(val)
			if err != nil {
				return nil, fmt.Errorf("lit: %w", err)
			}
			return lit(s), nil
		case "eq", "ne":
			ops, err := parseNodeList(val)
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
			ops, err := parseNodeList(val)
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
			child, err := parseNode(val)
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

func parseNodeList(raw json.RawMessage) ([]*Node, error) {
	var arr []json.RawMessage
	if err := json.Unmarshal(raw, &arr); err != nil {
		return nil, fmt.Errorf("expected an array of conditions: %w", err)
	}
	nodes := make([]*Node, len(arr))
	for i, r := range arr {
		n, err := parseNode(r)
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
	trace    []RuleTrace // structured, canonical record of every fold step (see trace.go)
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
	acc := Decision{Allow: false, Reason: "default-deny (no rule matched)"}
	for _, r := range rules {
		matched, attempts := traceMatch(r.Cond, q)
		before := acc.locked
		var outcome RuleOutcome
		acc, outcome = combine(acc, r, matched)
		acc.trace = append(acc.trace, RuleTrace{
			Name:     r.Name,
			Effect:   r.Effect,
			Outcome:  outcome,
			Decisive: acc.locked && !before, // this rule is the one that locked the verdict
			Attempts: attempts,
		})
	}
	return acc
}

// evalVerdict is the TRACE-OFF path: the same fold, computing only the verdict with the
// pure matcher and building no trace. It exists to prove that tracing has no effect on the
// decision — evaluate(...).Allow/Reason must equal evalVerdict(...).Allow/Reason.
func evalVerdict(rules []Rule, q Query, combine Strategy) Decision {
	acc := Decision{Allow: false, Reason: "default-deny (no rule matched)"}
	for _, r := range rules {
		acc, _ = combine(acc, r, matches(r.Cond, q))
	}
	return acc
}

// denyOverrides: any matching Deny is final and wins; a matching Allow sets the verdict
// but a later Deny can still override it. Absent any match, default-deny stands.
func denyOverrides(acc Decision, r Rule, matched bool) (Decision, RuleOutcome) {
	switch {
	case acc.locked:
		return acc, OutcomeSkipped
	case !matched:
		return acc, OutcomeNoMatch
	case r.Effect == Deny:
		acc.Allow, acc.Reason, acc.locked = false, "denied by "+r.Name, true
		return acc, OutcomeDeny
	default: // Allow
		acc.Allow, acc.Reason = true, "allowed by "+r.Name
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
		acc.Reason = fmt.Sprintf("%s by %s", r.Effect, r.Name)
		acc.locked = true
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
