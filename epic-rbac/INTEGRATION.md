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

## Absent, empty, and null attributes

Policies reference attributes by name. Their behaviour when a value is missing,
empty, or null is predictable and distinct — but has one subtlety worth knowing.

| Situation | Meaning | Decision | Trace |
|---|---|---|---|
| **Absent** | policy names an attribute the engine does not expose (e.g. `subject.dept`) | compares **false** against any concrete value | rendered `name=<absent>`, tagged `absent(name)` |
| **Present-empty** | an exposed attribute whose value is `""` (e.g. `scope` on a global check) | matches an empty-literal comparison; unequal to any non-empty value | rendered `name=""`, **present** (never `<absent>`) |
| **Null (condition)** | a `null` where a condition is expected | **rejected at parse** (fail closed) — never a silent match | n/a |
| **Null (value)** | a JSON `null` in a value position | collapses to the empty string `""` | as present-empty |

**Predictable rule:** an absent attribute makes comparisons against concrete values
false, and is always visibly distinct in the trace (`<absent>`) from a present empty
value.

**The subtlety:** in the *decision path* an absent attribute is read as `""`, so it
compares **equal** to an empty literal — identical to a present-empty value. The two
are separable only in the trace, not in the verdict. This means:

- Prefer comparing attributes to **concrete, non-empty** values in policy.
- Do not rely on `attr == ""` to mean "the attribute is set but empty"; an absent
  attribute satisfies it too.
- **Control absence at the source.** Because you resolve attributes from a trusted
  origin (per the contract above), whether an attribute is present is your decision
  to make deliberately, not an accident of request shape.

This absent-vs-empty gap is characterised by
`TestAttributeAbsentEqualsEmptyLiteralInDecisionButTraceDistinct` and the surrounding
tests in `attribute_contract_test.go`.

---

## Fail-closed posture (recap)

- No snapshot installed → **deny**.
- A malformed / oversized / pathological policy bundle is **rejected**, and the
  loader keeps the last known-good snapshot; a bad load never opens or clears access
  (TRUST-BOUNDARY.md, row 6).
- Absent attributes fail comparisons against concrete values; the engine never
  "opens" on missing data.

The engine will not save an integration from untrusted inputs — but given trusted
inputs, it is total, deterministic, and fails closed.
