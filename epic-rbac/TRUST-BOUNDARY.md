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
| 7 | Permit-always / overly-broad policy | Perimeter | **Policy source** (Story 4), not the evaluator | ✅ `TestByDesign_PermitAlwaysPolicyEvaluatedFaithfully` |
| 8 | Forged attributes (e.g. fake grant/`subject.roles`) | Perimeter | **Attribute-resolution trust boundary** (Story 3); origin is unrepresented by design | ✅ `TestByDesign_ForgedGrantIndistinguishableFromReal` |
| 9 | Injection-shaped attribute values (`admin'; permit all`, sigils) | Design | Opaque compare — no interpretation, no execution | ✅ `TestByDesign_InjectionShapedValuesAreOpaque` |
| 10 | Attribute sourced from request-controlled input | Perimeter | Documented attribute trust contract | ⏳ Story 3 |
| 11 | Malicious/tampered policy bundle becomes a snapshot | Perimeter | Authenticated/integrity-checked bundles before swap | ⏳ Story 4 |
| 12 | Full trace lets an end user probe the ruleset | Engine feature | Trace disclosure levels (full-to-logs vs minimal-to-user) | ⏳ Story 5 |

## Story status

- **Story 1 — Bound the parser (engine).** ✅ Done. Rows 1–6. Bounds:
  `maxPolicyBytes`, `maxRules`, `maxDepth`, `maxNodes`, `maxLiteralLen`; distinct
  zero/multi-key errors; `Holder.Load` fails closed to last known-good.
- **Story 2 — Prove-by-design (tests + findings).** ✅ Done. Rows 7–9. No engine
  code added (`bydesign_test.go` only exercises the existing evaluator). The
  demonstration technique is uniform, but the classifications split: row 9 is
  closed *by design* in the evaluator; rows 7–8 are closed *upstream* (perimeter),
  the tests proving why. Findings below.
- **Story 3 — Attribute trust contract (perimeter + docs).** ⏳ Row 10.
- **Story 4 — Policy source integrity (perimeter).** ⏳ Row 11.
- **Story 5 — Trace disclosure levels (engine feature).** ⏳ Row 12.

## Findings (Story 2 — prove-by-design)

All three are demonstrated with the same technique: a passing test showing the
engine evaluates the bad input **faithfully**, plus a written finding. No engine
code was added. But the *classifications differ*, and that distinction is the
point: injection is closed **by design** in the evaluator, while permit-always and
forged attributes are closed **upstream** — the tests prove the engine is faithful,
which is precisely *why* those two must be defended at the perimeter, not here.

**Finding 7 — Over-broad / permit-always policy.** *(Perimeter — closed upstream.)*
The engine faithfully evaluates any policy it is given, including one that permits
everything. It does not, and must not, judge a policy "too broad" — breadth is a
property of the policy, and the engine has no basis to override the author's intent
without inventing domain meaning. The threat is closed at the **policy source**
(Story 4): only trusted policy should ever become a snapshot. The test proves the
engine's faithful behavior — i.e. why the perimeter is required.
*Proof:* `TestByDesign_PermitAlwaysPolicyEvaluatedFaithfully`.

**Finding 8 — Forged attributes / grants.** *(Perimeter — closed upstream.)*
Forged-vs-authentic is not a distinction the engine can make, and that is a design
fact, not an omission: `Grant` has no provenance field, so two grants differing
only in origin are **unconstructible**. The engine evaluates whatever the query
carries; a fabricated allow grant is byte-for-byte an ordinary grant and is honored
as one. Because origin is unrepresented, forgery cannot be detected in the evaluator
without inventing a notion of "authentic" — a domain assumption that breaks
genericness. The threat is therefore closed **upstream** at the attribute/grant-
resolution trust boundary (Story 3): consumers MUST source identity/authorization
attributes from trusted origins. The by-design test proves the engine's faithful
behavior — i.e. why the perimeter is required.
*Proof:* `TestByDesign_ForgedGrantIndistinguishableFromReal`.

**Finding 9 — Injection-shaped values.** *(Design — closed in the evaluator.)*
Attribute values that look like SQL, policy fragments, CLI flags, sigils, or control
bytes are compared as opaque strings — equality only. Nothing is parsed, interpreted,
or executed; a payload matches only a literal equal to itself. The engine's
totality/purity (no input becomes code) *is* the injection defense; no perimeter is
needed. *Proof:* `TestByDesign_InjectionShapedValuesAreOpaque`.

## Invariants any future change must preserve

- No engine code gains input-distrust beyond parser bounding (rows 1–6).
- No engine code learns domain meaning. Grep guard over **non-test** source:
  `grep -rniE "invoice|role|admin|tenant|user" --include='*.go' --exclude='*_test.go' cmd/policyeval/`
  surfaces only the one genericness *disclaimer* comment in `main.go` ("knows
  nothing about … tenants, or any named role") — no domain logic. (Test fixtures
  deliberately contain injection tokens like `admin'; permit all`; that is data
  under test, not engine behaviour, so tests are excluded from the guard.)
- Determinism holds; trace-on and trace-off produce identical decisions.
- All malformed/partial/pathological policy fails closed to deny against the last
  known-good snapshot.
