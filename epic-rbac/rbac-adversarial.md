# Epic: Establish and Enforce the RBAC Engine's Trust Boundary

## Outcome

Every threat against the RBAC engine is classified as **closed by design**,
**closed by bounding the parser**, or **closed upstream (perimeter)** — with
tests proving the first two and documentation enforcing the third.

The deliverable is not a hardened engine. It is a **known and documented trust
boundary**: a clear statement of what the evaluator guarantees, what it
deliberately trusts, and where the security perimeter actually sits. The engine
is correct precisely because it interprets all input as opaque data and trusts
its inputs by contract; this epic proves that correctness and pushes the real
defenses to where they belong.

## Context

The engine is a generic Policy Decision Point: a pure function
`can(subject, action, resource, context) -> permit | deny + trace`, built as a
fold over a condition tree (`attr / lit / cmp / bool`), fed policy as immutable
versioned snapshots pulled live, with an explain/trace output.

Its safety properties (total, pure, terminating conditions; absent attribute →
false; fail-closed parsing) also serve as its primary injection defense: no
input ever becomes executable code. The remaining risk is not that the engine
is subverted, but that it **faithfully evaluates bad inputs** — malicious policy
or forged attributes. Those are perimeter problems, and naming them as such is
the point of this epic.

## Non-Goals

- **Do not add input-distrust to the engine core.** The engine's correctness
  rests on trusting its inputs (policy source, attribute bags). "Hardening" that
  away — e.g. having the engine try to detect forged roles or reject
  permit-always policies — violates the contract and breaks genericness.
- **Do not add domain assumptions** in the name of security. No engine code may
  learn what a role, resource, or attribute "means."
- Not building a policy-authoring UI, a real signing infrastructure rollout, or
  an attribute-resolution service — those are consumed/assumed, not built here.

---

## Story 1 — Bound the parser (engine hardening)

The one story that is pure engine code and closes a real denial-of-service
surface. A malicious policy that is technically valid but pathological must not
exhaust resources.

**Scope**
- Enforce a maximum condition-tree depth.
- Enforce a maximum policy size / rule count / literal size.
- Reject condition objects with zero keys or multiple keys (ambiguous dispatch)
  with a clear error, rather than silently picking one.
- Reject unknown node types, unknown operators, and wrong operand counts with
  clear, actionable messages.

**Acceptance criteria**
- A deeply nested policy (e.g. thousands of nested `and`s) is rejected at parse
  time; it never crashes, stack-overflows, or hangs.
- Oversized policies (huge rule count / giant literals) are rejected within a
  bounded time and memory envelope.
- Zero-key and two-key condition objects each produce a distinct error.
- All rejections **fail closed**: evaluation falls back to the last known-good
  snapshot and denies; a bad load never opens access.

---

## Story 2 — Prove-by-design, don't fix (engine tests + written finding)

For threats the engine closes *by design*, the deliverable is a passing test
**and** a written finding that says explicitly "the engine is correct here; the
perimeter is elsewhere." No engine-side defense is added.

**Scope**
- Permit-always / overly-broad policy: demonstrate the engine evaluates it
  faithfully, and document that this proves the perimeter is the **policy
  source**, not the evaluator.
- Forged attributes: demonstrate the engine cannot distinguish a forged
  `subject.roles` from a real one, and document that the defense is the
  **attribute-resolution trust boundary**, not the engine.
- Injection-shaped attribute values (`admin'; permit all`, `-x` tokens, sigils):
  demonstrate they are treated as opaque and compared unequal — no
  interpretation, no execution.

**Acceptance criteria**
- Tests pass showing faithful evaluation of these inputs.
- A short written finding accompanies each, classifying the threat and stating
  where the real defense lives.
- **No** engine code is added to "catch" these cases. Reviewer confirms the core
  gained no input-distrust and no domain assumptions.

---

## Story 3 — Attribute trust contract (perimeter + docs)

The engine cannot tell a real role from a forged one, so consumers must supply
identity/role attributes only from trusted sources. Because we will never meet
these consumers, the documented contract *is* the defense for this surface.

**Scope**
- Document, in the integration guide, that subject/identity attributes MUST come
  from verified sources (authenticated token, authoritative store) and NEVER
  from request-controlled input.
- Provide a worked example of correct vs incorrect attribute sourcing using
  generic (non-domain) fixtures.

**Acceptance criteria**
- Integration docs state the attribute trust contract explicitly and
  prominently.
- The contract is phrased so an integrator who never contacts us can follow it
  correctly.
- Tests over absent / empty / null attributes confirm predictable, distinct
  behavior (absent → comparison false) and correct trace rendering.

---

## Story 4 — Policy source integrity (perimeter)

Policy is pulled live and swapped into snapshots. A malicious snapshot is the
strongest attack, so its provenance must be trustworthy.

**Scope**
- Require authenticated / integrity-checked policy bundles (e.g. signed bundles
  or a trusted fetch channel) so a swapped snapshot cannot originate from an
  attacker.
- Verify integrity before a bundle becomes a snapshot; a failed check falls back
  to last known-good.

**Acceptance criteria**
- A tampered or untrusted policy bundle is rejected before it can become the
  current snapshot.
- Rejection falls back to the last known-good snapshot and denies new/unknown
  requests as appropriate — never opens access.
- Snapshot swap remains atomic; no in-flight decision observes a partial or
  malicious update.

---

## Story 5 — Trace disclosure levels (engine feature)

The only story here that is a genuine new engine capability. The explain/trace
output deliberately exposes inner workings; returning the full trace to an end
user could let an attacker probe the ruleset and shape a permitted request.

**Scope**
- Introduce trace disclosure levels: a **full** trace for the consuming app's
  logs, and a **minimal** reason surfaced to end users.
- Ensure the minimal reason cannot be used to reverse-engineer policy structure.
- Keep the full trace structurally rich: matched/skipped rules, deciding rule,
  per-node comparison results, absent-vs-unequal distinction, snapshot id, and
  how the combining strategy reached the result.

**Acceptance criteria**
- Full trace (to logs) captures the complete decision rationale, including
  absent-vs-unequal and the deciding snapshot id.
- End-user output is minimal and cannot be used to infer rule structure.
- Building the trace does not change the decision: trace-on and trace-off
  produce identical permit/deny results.

---

## Definition of Done (epic-level)

- **Every threat is classified**, not merely tested — labelled *closed by
  design*, *closed by bounding the parser*, or *closed upstream*. This
  classification is the epic's primary output: it tells future contributors
  where defenses belong and, crucially, where they must **not** be added.
- **No story added input-distrust to the engine core.** Confirmed by review: the
  evaluator still trusts its inputs by contract, and its correctness still rests
  on interpreting all input as opaque data.
- **No story introduced domain assumptions** into engine code. The grep test
  (`grep -ri "invoice|role|admin|tenant|user" internal/`) surfaces nothing but
  opaque primitives and clearly-marked test fixtures.
- **The drop-in test still passes**: the engine runs unchanged against a fresh,
  different-domain fixture world with new attributes and policies.
- Determinism holds: identical inputs always yield identical decisions;
  trace-on/trace-off are identical; no cross-call state dependence.
- Parser is bounded; all malformed / partial / pathological policy fails closed
  to deny against last known-good.
- The attribute trust contract and the policy-source integrity requirement are
  documented for consumers we will never meet.