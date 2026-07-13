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

**Classification** (category — *where* the threat is actually closed) and
**Demonstration** (technique — *how* we show it) are ORTHOGONAL axes and live in
separate columns. They are not the same thing: an upstream-closed threat can still
be demonstrated by an engine test (rows 7–8 are exactly that). Filing a row by its
technique is the bug this split prevents — a threat demonstrated in the engine
suite but actually closed at the perimeter must NOT read as "the engine handles
it," or the perimeter work silently never gets built.

**Classification** is assigned by the removal test, applied to each row's defense
independently: *if this defense were removed, where would the fix have to go?*

- Fix goes in the engine's own logic/behaviour → **By design**
- Fix goes in a parser limit/rejection → **By bounding the parser**
- Fix goes in the perimeter (policy source / attribute layer) → **Upstream**

**Demonstration** is how the classification is evidenced: an **engine test**, a
**documented contract** (the enforcement mechanism for upstream threats), or an
**engine feature** yet to be built.

| # | Threat | Classification | Demonstration | Defense location + proof |
|---|--------|----------------|---------------|--------------------------|
| 1 | Deeply-nested policy exhausts stack/CPU at parse | By bounding the parser | Engine test | `maxDepth`; `TestParserRejectsDeepNesting` |
| 2 | Wide policy (node blowup) exhausts memory | By bounding the parser | Engine test | `maxNodes`; `TestParserRejectsWideNodeCount` |
| 3 | Huge rule count / oversized document / giant literal | By bounding the parser | Engine test | `maxRules`/`maxPolicyBytes`/`maxLiteralLen`; `TestParserRejectsTooManyRules`, `…OversizedDocument`, `…HugeLiteral` |
| 4 | Ambiguous condition dispatch (0 or 2+ keys) | By bounding the parser | Engine test | Distinct parse errors; `TestParserZeroKeyVsMultiKeyDistinctErrors` |
| 5 | Unknown node type / operator / wrong operand count | By bounding the parser | Engine test | Clear parse rejection; `TestParserClearErrorsForMalformed` |
| 6 | Malformed/pathological load opens or clears access | By design | Engine test | `Holder.Load` fails closed to last known-good. Lives in Story 1 alongside the parser bound, but classified By design because the fail-closed *decision* is loader logic, not the bound itself. `TestBadLoadFailsClosedToLastKnownGood`, `…WithNoKnownGood…` |
| 7 | Permit-always / overly-broad policy | Upstream | Engine test (prove-by-design) | **Policy source** (Story 4); `TestByDesign_PermitAlwaysPolicyEvaluatedFaithfully` |
| 8 | Forged attributes (e.g. fake grant/`subject.roles`) | Upstream | Engine test (prove-by-design) | **Attribute-resolution boundary** (Story 3); provenance unrepresented in `Grant` by design; `TestByDesign_ForgedGrantIndistinguishableFromReal` |
| 9 | Injection-shaped attribute values (`admin'; permit all`, sigils) | By design | Engine test (prove-by-design) | Engine's opaque compare; `TestByDesign_InjectionShapedValuesAreOpaque` |
| 10 | Attribute sourced from request-controlled input | Upstream | Documented contract | ✅ Attribute trust contract in `INTEGRATION.md`; behaviour pinned by `attribute_contract_test.go` |
| 11 | Malicious/tampered policy bundle becomes a snapshot | Upstream | Mechanism + docs | ✅ `Holder.LoadBundle` verifies (injected `Verifier`) before parse+atomic swap; fails closed to last known-good; `integrity_test.go` |
| 12 | Full trace lets an end user probe the ruleset | By design | Engine feature | ✅ `Decision.Disclose(Full\|Minimal)`; minimal is a per-verdict constant, structure-free; `disclosure_test.go` |

### Reclassification log

Applying the removal test independently to every row changed four category labels
(none of the underlying demonstrations changed):

- **Row 6** Parser → **By design.** Remove `Holder.Load`'s fail-closed guard and the
  fix is engine loader logic (keep last known-good), not a parser bound. Two distinct
  defenses fire on the same input: the bound **rejects** the pathological policy (a
  parser concern), while failing closed **decides** what to do with a rejection — deny
  against last known-good (a loader concern). Row 6 is the second, and the tests assert
  that deny *consequence* (`h.Decide` still denies write, empty holder denies), not
  merely that the parser rejected. "Parser-adjacent" is context/provenance, not where
  the fix lives; filing it under bounding would reintroduce the technique-vs-category
  conflation.
- **Row 7** Design → **Upstream.** Remove trust in the policy source and the fix is
  vetting/signing that source — there is no engine logic to fix; the engine
  faithfully evaluates whatever it is handed.
- **Row 8** Design → **Upstream.** Provenance is unrepresented in `Grant` by design;
  remove the defense and there is nothing to fix *in the engine* because there was
  never engine logic there — the fix lives entirely at Story 3's boundary.
- **Row 12** "Engine feature" → **By design.** "Engine feature" named a technique,
  not a category. Remove trace disclosure levels and the fix is engine code (add the
  minimal/full split) → by design.

Rows 7–8 were first corrected in a prior commit; the removal-test audit confirms
them and additionally moves rows 6 and 12. Row 9 stays **By design** (remove the
opaque compare and the fix is engine code to restore it). Rows 10–11 are genuinely
**Upstream** (documented contract / integrity mechanism at the perimeter).

## Story status

- **Story 1 — Bound the parser (engine).** ✅ Done. Rows 1–6. Bounds:
  `maxPolicyBytes`, `maxRules`, `maxDepth`, `maxNodes`, `maxLiteralLen`; distinct
  zero/multi-key errors; `Holder.Load` fails closed to last known-good.
- **Story 2 — Prove-by-design (tests + findings).** ✅ Done. Rows 7–9. No engine
  code added (`bydesign_test.go` only exercises the existing evaluator). The
  demonstration technique is uniform, but the classifications split: row 9 is
  closed *by design* in the evaluator; rows 7–8 are closed *upstream* (perimeter),
  the tests proving why. Findings below.
- **Story 3 — Attribute trust contract (perimeter + docs).** ✅ Done. Row 10.
  `INTEGRATION.md` states the contract prominently (verified sources only, never
  request-controlled input) with a worked correct-vs-incorrect example on generic
  fixtures. `attribute_contract_test.go` pins absent/empty/null behaviour and trace
  rendering.
- **Follow-up (absent semantics correctness).** ✅ Done. Pinning surfaced a genuine
  discrepancy with the epic invariant "absent → comparison false": the engine had
  silently coerced an absent attribute to `""`, so `attr == lit("")` matched — absent
  was indistinguishable from present-empty in the verdict. Fixed as its own validated
  step (three-valued/Kleene logic): an absent operand is `unknown`, never `""`, and
  propagates through `==`/`!=`/`and`/`or`/`not` so it is never a match — including the
  negation trap `not(unknown) = unknown`. The invariant now has a tested guarantee
  (`TestAbsentIsNonMatchEvenAgainstEmptyLiteral`, `TestAbsentOperatorAudit`). This
  changed the evaluator, so it was done pin-wrong-first → fix → prove-the-flip, not
  patched into the net.
- **Story 4 — Policy source integrity (perimeter).** ✅ Done. Row 11. `LoadBundle`
  is the load-path trust seam: it runs an injected `Verifier` on the raw bundle
  BEFORE parsing or swapping, so unverified bytes never become a snapshot. Any
  failure — nil verifier, failed verification, or failed parse — is rejected and the
  last known-good snapshot stays installed; a bad bundle never opens or clears access.
  The swap is the existing atomic pointer store, so no in-flight decision sees a
  partial/malicious update (proven under `-race`). The engine performs no crypto
  itself (per the non-goal); the consumer supplies the `Verifier` (tests use an
  HMAC-SHA256 reference). `integrity_test.go`: verified installs, tampered/untrusted
  rejected + last known-good preserved, nil-verifier refused, verified-but-malformed
  rejected, concurrent atomicity.
- **Story 5 — Trace disclosure levels (engine feature).** ✅ Done. Row 12.
  `Decision.Disclose(level)` renders at two levels: **Full** (the app's logs —
  complete rationale: matched/skipped rules, deciding rule, per-node results,
  absent-vs-unequal, snapshot id, strategy) and **Minimal** (end users — a per-verdict
  constant, `access permitted`/`access denied`, revealing no structure). The zero value
  is Minimal, so an unset level fails safe. Every denial discloses the same minimal
  string regardless of cause, so it cannot be used to probe the ruleset. Rendering never
  changes the decision (`disclosure_test.go`, plus the standing trace-on/off invariant).

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

## Drop-in genericness — capstone (`TestDropIn_ForeignVocabulary`)

The DoD's drop-in test: a wholly foreign policy world (a content-moderation pipeline
— action vocabulary `publish`/`retract`/`escalate`, `channel-*` scopes, first-match
priority, `not`, and a foreign `clearance` attribute) run through the SAME engine
unchanged, parse → snapshot → evaluate → trace. It passed with **no engine change**,
and stands as a regression guard against structural leaks grep can't catch. It was
built to exercise two things the primary fixtures under-cover: **`not`** (no primary
policy fixture uses it) and **first-match as the lead strategy** (the capability demo
leans deny-overrides).

**Boundary the capstone surfaced (reported, not forced green).** The engine is generic
over *values* (opaque capabilities, scopes, needs) and over *structure* (any condition
tree, either strategy), but its attribute *vocabulary* is closed to
`{need, scope, grant.cap, grant.scope, grant.effect}` (`env.lookup`). A foreign
*matching* resource/context attribute — a real `clearance`, a `time` of day — is
therefore **not expressible**; it resolves as absent. So "generic RBAC engine" here
means a capability-grant model with opaque tokens, **not** an open attribute-bag ABAC
engine. Supporting arbitrary attributes would require changing `env.lookup` / `Query` /
`Grant` — an engine change deliberately NOT made (out of scope). In the capstone the
foreign attribute is exercised as the required absent case, confirming absent-is-a-
non-match holds in a domain the engine has never seen.

## Invariants any future change must preserve

- No engine code gains input-distrust beyond parser bounding (rows 1–6).
- No engine code learns domain meaning. Grep guard over **non-test** source:
  `grep -rniE "invoice|role|admin|tenant|user" --include='*.go' --exclude='*_test.go' cmd/policyeval/`
  surfaces only the one genericness *disclaimer* comment in `main.go` ("knows
  nothing about … tenants, or any named role") — no domain logic. (Test fixtures
  deliberately contain injection tokens like `admin'; permit all`; that is data
  under test, not engine behaviour, so tests are excluded from the guard.)
- Determinism holds; trace-on and trace-off produce identical decisions.
- Absent attributes are non-matches against every concrete value (including `""`) and
  never coerce to `""`; absence propagates by three-valued logic so it can never become
  a match via `!=` or `not`. Present-empty is distinct from absent in the verdict.
- The drop-in capstone (`TestDropIn_ForeignVocabulary`) runs a foreign vocabulary
  through the engine unchanged; a future baked-in structural assumption trips it red.
- All malformed/partial/pathological policy fails closed to deny against the last
  known-good snapshot.
