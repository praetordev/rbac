package rbac

import (
	"fmt"
	"strings"
)

// This file is the EXPLAIN layer. A consumer who authors policy and hits an unexpected
// deny needs to self-diagnose without asking the engine's author. The trace is that
// product feature: a machine-readable, structural account of exactly why a decision came
// out the way it did — canonical structured form (RuleTrace/CondTrace/ValueTrace) plus an
// optional human render (Decision.Explain) layered on top.
//
// Two principles:
//   - STRUCTURE, not strings. Nodes and effects are typed things; nothing is decoded from
//     mangled text. The renderer is the ONLY place words are chosen.
//   - Building the trace never changes the decision. The traced evaluators below mirror
//     evalBool/matches exactly (sharing applyCmp, mirroring short-circuit order); their
//     boolean results are guaranteed equal to the trace-off path.

// ---- Canonical structured trace ------------------------------------------------

// RuleOutcome classifies what happened to one rule during the fold. It is strategy-blind:
// the same four outcomes describe deny-overrides and first-match alike. Whether a matched
// Allow was provisional or decisive is carried by RuleTrace.Decisive, not by the outcome.
type RuleOutcome int

const (
	OutcomeNoMatch RuleOutcome = iota // the condition matched no grant the subject holds
	OutcomeAllow                      // matched, effect allow — set the verdict to permit
	OutcomeDeny                       // matched, effect deny — set the verdict to deny
	OutcomeSkipped                    // strategy did not consider this rule (verdict already locked)
)

func (o RuleOutcome) String() string {
	switch o {
	case OutcomeNoMatch:
		return "no-match"
	case OutcomeAllow:
		return "allow"
	case OutcomeDeny:
		return "deny"
	case OutcomeSkipped:
		return "skipped"
	}
	return "?"
}

// ValueTrace is how a value node (attr/literal) resolved. Present distinguishes an
// attribute that exists from one that is ABSENT — the single most important fact for
// diagnosing a silent deny. A literal is always present.
type ValueTrace struct {
	Kind    string // "attr" | "lit"
	Name    string // attribute name (Kind == "attr")
	Value   string // resolved value (meaningful only when Present)
	Present bool
}

// Absent reports whether this value is an absent attribute reference.
func (v ValueTrace) Absent() bool { return v.Kind == "attr" && !v.Present }

// CondTrace is how a bool-producing node (cmp/bool) evaluated. For cmp, Left/Right hold the
// compared values; for bool, Kids hold the sub-conditions actually evaluated (short-circuit
// means later kids may be omitted, exactly as the decision path skipped them).
type CondTrace struct {
	Kind        string       // "cmp" | "bool"
	Op          string       // cmp: "=="/"!="   bool: "and"/"or"/"not"
	Result      bool         // == evalBool(node) for this env
	Left, Right *ValueTrace  // cmp operands
	Kids        []*CondTrace // bool operands (evaluated ones, in order)
}

// GrantTrace records the condition tree evaluated against ONE candidate grant. Matching is
// existential over grants, so a rule accumulates one GrantTrace per grant tried, in order,
// stopping at the first that satisfies (Cond.Result == true).
type GrantTrace struct {
	Grant Grant
	Cond  *CondTrace
}

// RuleTrace is the per-rule record: its stable ID, outcome, whether it was the rule that
// locked the verdict, and the per-grant match attempts that justify the outcome.
type RuleTrace struct {
	ID       int
	Name     string
	Effect   Effect
	Outcome  RuleOutcome
	Decisive bool // this rule locked the verdict (the deciding rule)
	Attempts []GrantTrace
}

// Matched reports whether some grant satisfied the rule's condition.
func (rt RuleTrace) Matched() bool {
	n := len(rt.Attempts)
	return n > 0 && rt.Attempts[n-1].Cond.Result
}

// deciderCond returns the grant attempt that best explains the outcome: for a matched rule,
// the satisfying (last) attempt; otherwise nil (non-matches are explained per grant).
func (rt RuleTrace) deciderCond() *GrantTrace {
	if rt.Matched() {
		return &rt.Attempts[len(rt.Attempts)-1]
	}
	return nil
}

// Trace is the canonical, machine-readable form of a decision's explanation. It is a pure
// projection of the Decision — no words, just structure — suitable for logging as JSON or
// asserting against in tests.
type Trace struct {
	Snapshot string
	Allow    bool
	Reason   string
	Rules    []RuleTrace
}

// Trace exposes the structured explanation. This is the canonical form; Explain renders it.
func (d Decision) Trace() Trace {
	return Trace{Snapshot: d.Snapshot, Allow: d.Allow, Reason: d.Reason, Rules: d.trace}
}

// ---- Traced evaluators (mirror evalBool/matches, never change the decision) -----

// traceValue resolves a value node into a ValueTrace, recording presence/absence.
func traceValue(n *Node, e env) *ValueTrace {
	switch n.Kind {
	case KindAttr:
		v, present := e.lookup(n.Attr)
		return &ValueTrace{Kind: "attr", Name: n.Attr, Value: v, Present: present}
	case KindLiteral:
		return &ValueTrace{Kind: "lit", Value: n.Literal, Present: true}
	default:
		panic("condition: expected a value node (attr/literal)")
	}
}

// traceCond mirrors evalTri, building a CondTrace whose Result (definitely-true) is
// guaranteed equal to evalBool for the same node/env. It carries the three-valued result
// internally so absent-driven `unknown` propagates identically to the decision path; the
// exported CondTrace.Result is `tri == triTrue`. An absent operand is visible via the
// ValueTrace's Present flag, so the render can still distinguish absent from present-unequal.
func traceCond(n *Node, e env) *CondTrace {
	ct, _ := traceCondTri(n, e)
	return ct
}

func traceCondTri(n *Node, e env) (*CondTrace, tri) {
	switch n.Kind {
	case KindCmp:
		l, r := traceValue(n.Left, e), traceValue(n.Right, e)
		var t tri
		if !l.Present || !r.Present {
			t = triUnknown
		} else {
			t = triOf(applyCmp(n.Op, l.Value, r.Value))
		}
		return &CondTrace{Kind: "cmp", Op: n.Op, Left: l, Right: r, Result: t == triTrue}, t
	case KindBool:
		ct := &CondTrace{Kind: "bool", Op: n.Op}
		switch n.Op {
		case "and":
			r := triTrue
			for _, k := range n.Kids {
				kt, kv := traceCondTri(k, e)
				ct.Kids = append(ct.Kids, kt)
				if kv == triFalse { // false dominates — short-circuit exactly like evalTri
					ct.Result = false
					return ct, triFalse
				}
				if kv == triUnknown {
					r = triUnknown
				}
			}
			ct.Result = r == triTrue
			return ct, r
		case "or":
			r := triFalse
			for _, k := range n.Kids {
				kt, kv := traceCondTri(k, e)
				ct.Kids = append(ct.Kids, kt)
				if kv == triTrue { // true dominates — short-circuit exactly like evalTri
					ct.Result = true
					return ct, triTrue
				}
				if kv == triUnknown {
					r = triUnknown
				}
			}
			ct.Result = r == triTrue
			return ct, r
		case "not":
			kt, kv := traceCondTri(n.Kids[0], e)
			ct.Kids = append(ct.Kids, kt)
			var t tri
			switch kv {
			case triTrue:
				t = triFalse
			case triFalse:
				t = triTrue
			default:
				t = triUnknown
			}
			ct.Result = t == triTrue
			return ct, t
		}
	}
	panic("condition: expected a bool node (cmp/bool)")
}

// traceMatch mirrors matches: existential over grants, short-circuiting at the first
// satisfying grant. It returns the same bool as matches plus the per-grant attempts.
func traceMatch(cond *Node, q Query) (bool, []GrantTrace) {
	attempts := make([]GrantTrace, 0, len(q.Grants))
	for _, g := range q.Grants {
		ct := traceCond(cond, env{q: q, g: g})
		attempts = append(attempts, GrantTrace{Grant: g, Cond: ct})
		if ct.Result {
			return true, attempts
		}
	}
	return false, attempts
}

// ---- Disclosure levels -----------------------------------------------------------

// Disclosure controls how much of a decision's rationale is revealed.
//
// Full is for the CONSUMING APP'S OWN LOGS: the complete rationale — matched/skipped rules,
// the deciding rule, per-node comparison results, absent-vs-unequal, the snapshot id, and how
// the combining strategy reached the verdict. It deliberately exposes policy structure.
//
// Minimal is safe to surface to the REQUESTER (the party whose access was decided): the
// verdict, and nothing else. It is identical for every permit and identical for every deny,
// so it cannot be used to probe or reverse-engineer the ruleset — a denial caused by an
// absent attribute, an explicit deny, a default-deny, or a fail-closed nil snapshot all read
// the same.
//
// The zero value is Minimal, so a caller that forgets to choose a level fails SAFE (reveals
// the least). Correlating a requester-facing denial with its full logged trace is the
// consumer's job — log Full alongside your own request id. The engine adds no identifier of
// its own, so it stays deterministic.
type Disclosure int

const (
	Minimal Disclosure = iota // requester-safe: verdict only, no structure
	Full                      // app logs: complete rationale
)

// Disclose renders the decision at the given disclosure level. Rendering is a pure read of an
// already-computed decision; it never changes the verdict, and neither level's output feeds
// back into the decision.
func (d Decision) Disclose(level Disclosure) string {
	if level == Full {
		return d.Explain()
	}
	return d.minimalReason()
}

// minimalReason is the structure-free, requester-safe reason: a constant per verdict. It
// names no rule, attribute, snapshot, or cause, so no two denials (or permits) are
// distinguishable from it.
func (d Decision) minimalReason() string {
	if d.Allow {
		return "access permitted"
	}
	return "access denied"
}

// ---- Human render (layered on the structured form; the only place words live) ---

// Explain renders a decision's structured trace for a human reader. It reports the final
// verdict and snapshot, then each rule considered, and — for matched/deciding and
// non-matching rules — drills into the condition nodes, calling out absent attributes
// distinctly from present-but-unequal comparisons.
func (d Decision) Explain() string {
	var b strings.Builder
	verdict := "DENY "
	if d.Allow {
		verdict = "ALLOW"
	}
	if d.Snapshot != "" {
		fmt.Fprintf(&b, "snapshot %s → %s  (%s)\n", d.Snapshot, verdict, d.Reason)
	} else {
		fmt.Fprintf(&b, "%s  (%s)\n", verdict, d.Reason)
	}

	if len(d.trace) == 0 {
		b.WriteString("      (no rules evaluated)\n")
		return strings.TrimRight(b.String(), "\n")
	}

	for _, rt := range d.trace {
		fmt.Fprintf(&b, "  %s %-16s %s%s\n", outcomeMark(rt), rt.Name, rt.Outcome, decisiveTag(rt))
		for _, line := range explainRule(rt) {
			fmt.Fprintf(&b, "      %s\n", line)
		}
	}
	fmt.Fprintf(&b, "  ⇒ %s\n", strategyStory(d))
	return strings.TrimRight(b.String(), "\n")
}

// explainRule produces the node-level detail lines for one rule: the satisfying grant for a
// matched rule, every attempted grant for a non-match, and nothing for a skipped rule.
func explainRule(rt RuleTrace) []string {
	switch rt.Outcome {
	case OutcomeSkipped:
		return nil
	case OutcomeAllow, OutcomeDeny:
		gt := rt.deciderCond()
		lines := []string{"via grant " + describeGrant(gt.Grant) + ":"}
		return append(lines, indent(renderCond(gt.Cond, ""), "  ")...)
	default: // OutcomeNoMatch — explain why each candidate grant failed
		if len(rt.Attempts) == 0 {
			return []string{"no grants to test (nothing can match)"}
		}
		var lines []string
		for _, gt := range rt.Attempts {
			lines = append(lines, "grant "+describeGrant(gt.Grant)+":")
			lines = append(lines, indent(renderCond(gt.Cond, ""), "  ")...)
		}
		return lines
	}
}

// renderCond renders a CondTrace as indented lines. Comparisons show both operands with
// their resolved values, an explicit absent tag when an operand attribute is missing, and
// the boolean result.
func renderCond(c *CondTrace, indentStr string) []string {
	switch c.Kind {
	case "cmp":
		line := fmt.Sprintf("%s%s %s %s → %v", indentStr, renderValue(c.Left), c.Op, renderValue(c.Right), c.Result)
		if a := absentOperands(c); a != "" {
			line += ": absent(" + a + ")"
		}
		return []string{line}
	case "bool":
		head := fmt.Sprintf("%s%s → %v", indentStr, strings.ToUpper(c.Op), c.Result)
		lines := []string{head}
		for _, k := range c.Kids {
			lines = append(lines, renderCond(k, indentStr+"  ")...)
		}
		return lines
	}
	return nil
}

// renderValue shows a value node: a literal in quotes, a present attribute as name=value,
// and an absent attribute as name=<absent> so absence is unmistakable.
func renderValue(v *ValueTrace) string {
	if v.Kind == "lit" {
		return fmt.Sprintf("%q", v.Value)
	}
	if !v.Present {
		return v.Name + "=<absent>"
	}
	return fmt.Sprintf("%s=%q", v.Name, v.Value)
}

// absentOperands names the absent attribute operands of a comparison (if any).
func absentOperands(c *CondTrace) string {
	var names []string
	if c.Left != nil && c.Left.Absent() {
		names = append(names, c.Left.Name)
	}
	if c.Right != nil && c.Right.Absent() {
		names = append(names, c.Right.Name)
	}
	return strings.Join(names, ", ")
}

// strategyStory synthesises the one-line account of how the fold reached its verdict,
// making a deny that beat a permit explicit. It reads only the structured outcomes.
func strategyStory(d Decision) string {
	var permitted, denied []string
	var decider string
	for _, rt := range d.trace {
		switch rt.Outcome {
		case OutcomeAllow:
			permitted = append(permitted, rt.Name)
		case OutcomeDeny:
			denied = append(denied, rt.Name)
		}
		if rt.Decisive {
			decider = rt.Name
		}
	}
	switch {
	case d.Allow:
		who := decider // decisive rule under first-match; empty under deny-overrides (allow is provisional)
		if who == "" && len(permitted) > 0 {
			who = permitted[len(permitted)-1]
		}
		return fmt.Sprintf("ALLOW — %s permitted", who)
	case len(denied) > 0 && len(permitted) > 0:
		return fmt.Sprintf("DENY — %s denied, overriding permit from %s",
			strings.Join(denied, ", "), strings.Join(permitted, ", "))
	case len(denied) > 0:
		return fmt.Sprintf("DENY — %s denied", strings.Join(denied, ", "))
	default:
		return "DENY — no rule matched (default-deny)"
	}
}

// describeGrant renders a grant opaquely: effect, capability, scope — never interpreting.
func describeGrant(g Grant) string {
	scope := g.Scope
	if scope == "" {
		scope = "*global*"
	}
	return fmt.Sprintf("%s %s@%s", g.Effect.token(), g.Capability, scope)
}

func outcomeMark(rt RuleTrace) string {
	switch rt.Outcome {
	case OutcomeAllow:
		return "✓"
	case OutcomeDeny:
		return "✗"
	default:
		return "·"
	}
}

func decisiveTag(rt RuleTrace) string {
	if rt.Decisive {
		return " (decisive)"
	}
	if rt.Outcome == OutcomeAllow {
		return " (provisional)"
	}
	return ""
}

func indent(lines []string, pad string) []string {
	out := make([]string, len(lines))
	for i, l := range lines {
		out[i] = pad + l
	}
	return out
}
