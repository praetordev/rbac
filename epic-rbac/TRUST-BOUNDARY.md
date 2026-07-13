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
| 7 | Permit-always / overly-broad policy | Design | **Policy source** (Story 4), not the evaluator | ✅ `TestByDesign_PermitAlwaysPolicyEvaluatedFaithfully` |
| 8 | Forged attributes (e.g. fake grant/`subject.roles`) | Design | **Attribute-resolution trust boundary** (Story 3) | ✅ `TestByDesign_ForgedGrantIndistinguishableFromReal` |
| 9 | Injection-shaped attribute values (`admin'; permit all`, sigils) | Design | Opaque compare — no interpretation, no execution | ✅ `TestByDesign_InjectionShapedValuesAreOpaque` |
| 10 | Attribute sourced from request-controlled input | Perimeter | Documented attribute trust contract | ⏳ Story 3 |
| 11 | Malicious/tampered policy bundle becomes a snapshot | Perimeter | Authenticated/integrity-checked bundles before swap | ⏳ Story 4 |
| 12 | Full trace lets an end user probe the ruleset | Engine feature | Trace disclosure levels (full-to-logs vs minimal-to-user) | ⏳ Story 5 |

## Story status

- **Story 1 — Bound the parser (engine).** ✅ Done. Rows 1–6. Bounds:
  `maxPolicyBytes`, `maxRules`, `maxDepth`, `maxNodes`, `maxLiteralLen`; distinct
  zero/multi-key errors; `Holder.Load` fails closed to last known-good.
- **Story 2 — Prove-by-design (tests + findings).** ✅ Done. Rows 7–9. No engine
  code added (`bydesign_test.go` only exercises the existing evaluator); findings
  below.
- **Story 3 — Attribute trust contract (perimeter + docs).** ⏳ Row 10.
- **Story 4 — Policy source integrity (perimeter).** ⏳ Row 11.
- **Story 5 — Trace disclosure levels (engine feature).** ⏳ Row 12.

## Findings — closed by design (Story 2)

Each of these is a threat the engine closes *by design*. No engine code was added
to "catch" them; the demonstration is that the engine evaluates them **faithfully**
and the real defense lives elsewhere.

**Finding 7 — Over-broad / permit-always policy.** The engine faithfully evaluates
any policy it is given, including one that permits everything. It does not, and
must not, judge a policy "too broad" — breadth is a property of the policy, and
the engine has no basis to override the author's intent without inventing domain
meaning. *Defense:* the **policy source** (Story 4) — only trusted policy should
ever become a snapshot. *Proof:* `TestByDesign_PermitAlwaysPolicyEvaluatedFaithfully`.

**Finding 8 — Forged attributes / grants.** The engine evaluates the grants and
attributes the query carries and has no notion of where they came from; a
fabricated allow grant is byte-for-byte indistinguishable from a legitimately
issued one. Having the engine try to detect forgery would require it to know what
a "real" grant looks like — a domain assumption that breaks genericness.
*Defense:* the **attribute/grant-resolution trust boundary** (Story 3) — consumers
MUST source identity/authorization attributes from trusted origins.
*Proof:* `TestByDesign_ForgedGrantIndistinguishableFromReal`.

**Finding 9 — Injection-shaped values.** Attribute values that look like SQL,
policy fragments, CLI flags, sigils, or control bytes are compared as opaque
strings — equality only. Nothing is parsed, interpreted, or executed; a payload
matches only a literal equal to itself. The engine's totality/purity (no input
becomes code) *is* the injection defense. *Defense:* closed by design in the
evaluator; no perimeter needed. *Proof:* `TestByDesign_InjectionShapedValuesAreOpaque`.

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
