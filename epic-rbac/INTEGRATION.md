# Integration Guide — Generic RBAC Engine

This guide is written for integrators we will never meet. The engine is a pure
Policy Decision Point: `decide(query, snapshot) -> permit | deny + trace`. It is
generic and domain-blind — it compares opaque strings and interprets nothing.

Because it trusts its inputs by contract, **the safety of an integration depends on
where those inputs come from**. This guide states the two contracts you must honour.
See [TRUST-BOUNDARY.md](TRUST-BOUNDARY.md) for the full threat classification.

---

## ⚠️ Attribute Trust Contract (read this first)

> **Identity and authorization attributes — the subject's grants, and any
> `subject.*` attributes a policy references — MUST be resolved from a VERIFIED
> source. They MUST NEVER be taken from request-controlled input.**

**Why this is your responsibility, not the engine's.** The engine cannot tell a
forged grant from an authentic one. Provenance is *unrepresented by design*: a
`Grant` carries a capability, a scope, and an effect — never where it came from.
Two grants that differ only in origin are indistinguishable to the evaluator, so it
honours whatever the query holds (see TRUST-BOUNDARY.md, row 8 / Finding 8). The
defense therefore lives entirely at your boundary: **source attributes from trust,
and the forged-attribute threat is closed; source them from the request, and it is
wide open.**

**MUST — verified sources:**
- Claims from an authenticated, integrity-checked token (e.g. a validated session
  or signed assertion).
- An authoritative store keyed by the *authenticated* principal.

**MUST NOT — attacker-controlled sources:**
- Request body, query string, headers, or cookies the caller can set.
- Any grant or attribute the client asserts about itself.

### Worked example — correct vs incorrect sourcing (generic fixtures)

The subject wants capability `cap.write` at scope `res-42`. Everything below is
opaque: `cap.write` and `res-42` mean nothing to the engine.

**❌ INCORRECT — grants sourced from request-controlled input.** The client sends
its own grants in the request body; the server trusts them.

```
// req.Body is fully attacker-controlled.
var claimed []Grant
json.Unmarshal(req.Body, &claimed)          // client says: "I hold cap.write @ res-42 (allow)"

q := Query{Grants: claimed, Need: "cap.write", Scope: "res-42"}
decision := holder.Decide(q)                 // engine faithfully permits the forged grant
```

The attacker simply declares the grant they want. The engine is not fooled — it is
doing exactly its job — but the access is granted because the *input* was forged.

**✅ CORRECT — grants resolved from a trusted store by the authenticated principal.**

```
principal := auth.PrincipalFromValidatedToken(req)   // identity comes from a verified token
grants := grantStore.GrantsFor(principal)            // authoritative store, not the request

q := Query{Grants: grants, Need: "cap.write", Scope: "res-42"}
decision := holder.Decide(q)                         // engine evaluates only trusted grants
```

The request influences *what is being asked* (`Need`/`Scope`), never *what the
subject holds*. The engine's behaviour is identical in both cases — the only
difference is the trustworthiness of the input, which is yours to guarantee.

---

## ⚠️ Policy Source Integrity Contract

> **A policy bundle MUST be verified as authentic before it becomes a snapshot. Load
> untrusted bundles only through `Holder.LoadBundle` with a `Verifier` that establishes
> trust (a signature you check, or a bundle fetched over an authenticated channel).**

A swapped-in malicious snapshot is the strongest attack on the engine — it rewrites the
policy itself. The engine cannot judge a policy's *provenance* any more than a grant's
(it faithfully evaluates whatever snapshot is current), so integrity is your boundary.

`LoadBundle(id, bundle, verify, combine)` enforces the ordering that makes this safe:

1. **Verify first** — your `Verifier` runs on the raw bundle; unverified bytes are never
   parsed or installed.
2. **Parse under bounds** — a verified-but-malformed bundle still fails (Story 1 limits).
3. **Swap atomically** — installation is a single atomic pointer store; no in-flight
   decision ever observes a partial or malicious update.

Any failure — no verifier, failed verification, or failed parse — is rejected and the
**last known-good snapshot stays installed**. A bad bundle can never become current,
clear the policy, or open access.

```
// You supply the trust anchor; the engine performs no crypto of its own.
verify := func(bundle []byte) (policy []byte, err error) {
    return checkSignature(bundle, trustedPublicKey) // your signature / channel check
}
if err := holder.LoadBundle(version, bundle, verify, denyOverrides); err != nil {
    log.Warn("policy update rejected, still serving last known-good:", err)
}
```

The engine ships only this seam — real signing/verification is yours to provide. Never
bypass it by parsing an untrusted bundle directly into a snapshot.

## Absent, empty, and null attributes

Policies reference attributes by name. Their behaviour when a value is missing,
empty, or null is predictable, and absent is **distinct from empty in the verdict**,
not just the trace.

| Situation | Meaning | Decision | Trace |
|---|---|---|---|
| **Absent** | policy names an attribute the engine does not expose (e.g. `subject.dept`) | a **non-match** against every concrete value, **including `""`** | rendered `name=<absent>`, tagged `absent(name)` |
| **Present-empty** | an exposed attribute whose value is `""` (e.g. `scope` on a global check) | **matches** an empty-literal comparison; unequal to any non-empty value | rendered `name=""`, **present** (never `<absent>`) |
| **Null (condition)** | a `null` where a condition is expected | **rejected at parse** (fail closed) — never a silent match | n/a |
| **Null (value)** | a JSON `null` in a value position | collapses to the empty string `""`, then behaves as present-empty | as present-empty |

### The absent-attribute rule (three-valued logic)

An absent operand makes its comparison **unknown** — never true, never coerced to
`""`. Unknown propagates by Kleene logic, applied uniformly to every operator:

- `==` / `!=` with an absent operand → **unknown** (an absent value is neither equal
  nor unequal to anything).
- `and` → false if any branch is false; else unknown if any is unknown; else true.
- `or` → true if any branch is true; else unknown if any is unknown; else false.
- `not(unknown)` → **unknown** (negating an absent comparison stays a non-match — it
  can never flip absence into a match).

**A rule matches only when its condition is definitely true.** Unknown and false are
both non-matches, so:

- An absent attribute never causes a match — not via `==`, not via `!=`, not via
  `not(...)`.
- `attr == ""` means "the attribute is present and empty" — an absent attribute does
  **not** satisfy it. (This was previously a footgun: the engine silently read absent
  as `""` and matched; it is now corrected — see TRUST-BOUNDARY.md, row 10.)
- `or` still tolerates a missing attribute if another branch is definitely true; `and`
  fails closed if any branch depends on missing data.

This behaviour is pinned by `attribute_contract_test.go`
(`TestAbsentIsNonMatchEvenAgainstEmptyLiteral`, `TestAbsentOperatorAudit`, and the
absent/empty cases).

---

## Trace disclosure — logs vs end users

A decision carries a rich trace so authors can self-diagnose denials. That same trace
would let an attacker probe and reverse-engineer your ruleset, so choose the audience
explicitly with `Decision.Disclose(level)`:

- **`Disclose(Full)` → your own logs.** The complete rationale: which rules matched or
  were skipped, the deciding rule, per-node comparison results, absent-vs-unequal, the
  snapshot id, and how the strategy reached the verdict.
- **`Disclose(Minimal)` → the end user.** The verdict only — `access permitted` or
  `access denied`. It is a constant per verdict, so every denial looks identical: a
  default-deny, an explicit deny, an absent-attribute deny, and a fail-closed deny are
  indistinguishable. Nothing about the ruleset leaks.

```
decision := holder.Decide(q)
log.Info(requestID, decision.Disclose(Full))   // to your logs, with YOUR correlation id
http.Error(w, decision.Disclose(Minimal), 403) // to the caller — structure-free
```

**The zero value of `Disclosure` is `Minimal`**, so forgetting to choose a level fails
safe (reveals the least). The engine adds no identifier of its own — to correlate a
user-facing denial with its full logged trace, log `Full` alongside your own request id.

## Fail-closed posture (recap)

- No snapshot installed → **deny**.
- A malformed / oversized / pathological policy bundle is **rejected**, and the
  loader keeps the last known-good snapshot; a bad load never opens or clears access
  (TRUST-BOUNDARY.md, row 6).
- Absent attributes fail comparisons against concrete values; the engine never
  "opens" on missing data.

The engine will not save an integration from untrusted inputs — but given trusted
inputs, it is total, deterministic, and fails closed.
