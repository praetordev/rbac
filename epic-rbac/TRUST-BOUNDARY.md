# RBAC Engine — Trust Boundary

> Living document. The epic's primary deliverable is not a hardened engine — it
> is this **classification**: for every threat, whether it is *closed by design*,
> *closed by bounding the parser*, or *closed upstream (perimeter)*, and where the
> real defense therefore lives. It tells future contributors where defenses
> belong and, crucially, where they must **not** be added.

## What the engine guarantees

The engine is a pure Policy Decision Point:
`decide(query, snapshot) -> permit | deny + trace`, a fold over a condition tree
(`attr / lit / cmp / bool`) fed immutable versioned snapshots.

- **Total, pure, terminating.** Conditions cannot loop or call out; evaluation
  always halts with a decision. Identical inputs yield identical decisions.
- **Everything is opaque data.** Capability tokens, scopes, attribute names and
  values are compared as strings. No input ever becomes executable code; the
  engine never learns what a role, resource, or attribute "means".
- **Absent is not empty.** A missing attribute is first-class and makes a
  comparison false — distinct from a present empty string.
- **Fail closed.** No snapshot, a malformed load, or a nil decision path denies.
  A bad policy load never opens access and never clears the installed policy.

## What the engine trusts by contract

The engine's correctness *rests on* trusting its inputs. It faithfully evaluates
whatever policy and attributes it is given. That is a feature, not a gap:

- **Policy is trusted input.** Its provenance/integrity is a perimeter concern
  (Story 4), not something the evaluator second-guesses.
- **Attributes are trusted input.** The engine cannot tell a real `subject.roles`
  from a forged one; supplying them from trusted sources is the consumer's job
  (Story 3).

Adding input-distrust to the core (detecting "forged" roles, rejecting
"permit-always" policies) would violate the contract and break genericness. The
one exception is parser bounding (Story 1) — and only because it guards the
engine's own **liveness**, not the meaning of any input.

## Classification

Legend — **Design**: closed by design, no engine change. **Parser**: closed by
bounding the parser. **Perimeter**: closed upstream; the documented contract is
the defense.

| # | Threat | Class | Where the defense lives | Proof / status |
|---|--------|-------|-------------------------|----------------|
| 1 | Deeply-nested policy exhausts stack/CPU at parse | Parser | `maxDepth` bound | ✅ `TestParserRejectsDeepNesting` |
| 2 | Wide policy (node blowup) exhausts memory | Parser | `maxNodes` budget | ✅ `TestParserRejectsWideNodeCount` |
| 3 | Huge rule count / oversized document / giant literal | Parser | `maxRules` / `maxPolicyBytes` / `maxLiteralLen` | ✅ `TestParserRejectsTooManyRules`, `…OversizedDocument`, `…HugeLiteral` |
| 4 | Ambiguous condition dispatch (0 or 2+ keys) | Parser | Distinct, actionable parse errors | ✅ `TestParserZeroKeyVsMultiKeyDistinctErrors` |
| 5 | Unknown node type / operator / wrong operand count | Parser | Clear rejection at parse | ✅ `TestParserClearErrorsForMalformed` |
| 6 | Malformed/pathological load opens or clears access | Parser (fail closed) | `Holder.Load` keeps last known-good; empty stays deny | ✅ `TestBadLoadFailsClosedToLastKnownGood`, `…WithNoKnownGood…` |
| 7 | Permit-always / overly-broad policy | Design | **Policy source** (Story 4), not the evaluator | ⏳ Story 2 |
| 8 | Forged attributes (e.g. fake `subject.roles`) | Design | **Attribute-resolution trust boundary** (Story 3) | ⏳ Story 2 |
| 9 | Injection-shaped attribute values (`admin'; permit all`, sigils) | Design | Opaque compare — no interpretation, no execution | ⏳ Story 2 |
| 10 | Attribute sourced from request-controlled input | Perimeter | Documented attribute trust contract | ⏳ Story 3 |
| 11 | Malicious/tampered policy bundle becomes a snapshot | Perimeter | Authenticated/integrity-checked bundles before swap | ⏳ Story 4 |
| 12 | Full trace lets an end user probe the ruleset | Engine feature | Trace disclosure levels (full-to-logs vs minimal-to-user) | ⏳ Story 5 |

## Story status

- **Story 1 — Bound the parser (engine).** ✅ Done. Rows 1–6. Bounds:
  `maxPolicyBytes`, `maxRules`, `maxDepth`, `maxNodes`, `maxLiteralLen`; distinct
  zero/multi-key errors; `Holder.Load` fails closed to last known-good.
- **Story 2 — Prove-by-design (tests + findings).** ⏳ Rows 7–9. No engine code
  to be added; each row gets a passing test and a written finding here.
- **Story 3 — Attribute trust contract (perimeter + docs).** ⏳ Row 10.
- **Story 4 — Policy source integrity (perimeter).** ⏳ Row 11.
- **Story 5 — Trace disclosure levels (engine feature).** ⏳ Row 12.

## Invariants any future change must preserve

- No engine code gains input-distrust beyond parser bounding (rows 1–6).
- No engine code learns domain meaning. Grep guard:
  `grep -riE "invoice|role|admin|tenant|user" cmd/policyeval/*.go` surfaces only
  opaque primitives, clearly-marked test fixtures, and the one genericness
  *disclaimer* comment in `main.go` ("knows nothing about … tenants, or any named
  role") — no domain logic.
- Determinism holds; trace-on and trace-off produce identical decisions.
- All malformed/partial/pathological policy fails closed to deny against the last
  known-good snapshot.
