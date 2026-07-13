# rbac

A generic, capability-grant authorization engine for Go — a pure Policy Decision Point
that answers *"may this request proceed?"*

The engine is deliberately **domain-blind**: capabilities and scopes are opaque strings it
compares but never interprets. It has no built-in content types, actions, or roles — your
vocabulary lives entirely in the policy data. Policy is authored as a small JSON condition
tree, parsed once into an immutable, versioned snapshot, and evaluated with a fold over an
ordered rule list.

```
import "github.com/praetordev/rbac/v4"
```

## Quickstart

Parse a policy into a snapshot, ask a question, read the verdict:

```go
package main

import (
    "fmt"

    rbac "github.com/praetordev/rbac/v4"
)

func main() {
    // A policy bundle: allow when the subject holds a matching, allowing grant.
    policy := []byte(`[
      {"name":"allow-matching-grant","effect":"allow","when":{"all":[
        {"eq":[{"attr":"grant.effect"},{"lit":"allow"}]},
        {"eq":[{"attr":"grant.cap"},{"attr":"need"}]},
        {"eq":[{"attr":"grant.scope"},{"attr":"scope"}]}
      ]}}
    ]`)

    snap, err := rbac.NewSnapshot("fleet-v1", policy, rbac.DenyOverrides)
    if err != nil {
        panic(err)
    }

    // Grants resolved from a trusted store keyed by a verified identity — never the request.
    q := rbac.Query{
        Grants: []rbac.Grant{{Capability: "launch", Scope: "ship-9", Effect: rbac.Allow}},
        Need:   "launch",
        Scope:  "ship-9",
    }

    d := rbac.Decide(snap, q)
    fmt.Println(d.Allow) // true
    if ref, ok := d.Decider(); ok {
        fmt.Printf("decided by rule #%d %q\n", ref.ID, ref.Name)
    }
}
```

The question is a `Query{Grants, Need, Scope}`; the answer is a `Decision` — `Allow`, plus
`Decider()` naming the rule that decided (by stable `ID`, never by name). The four-part RBAC
mental model maps onto the real inputs as **subject → `Query.Grants`**, **action →
`Query.Need`**, **resource → `Query.Scope`**; there is no `context` input (see below).

## Authoring a policy bundle

A bundle is a JSON array of rules; each is `{ "name", "effect": "allow"|"deny", "when": <condition> }`.
A `when` tree is built from single-key nodes: values `attr` / `lit`, comparisons `eq` / `ne`,
and combinators `all` / `any` / `not`. A rule matches when *some* grant the subject holds
makes its `when` tree true. The combining strategy — `DenyOverrides` (a matching deny is a
veto) or `FirstMatch` (first matching rule wins, so order is the policy) — folds the rules
into one verdict.

## Live policy: sources, snapshots, atomic swap

Policy can be fetched from a swappable `Source` and hot-swapped without a rewrite. The
`Loader` fetches, parses once per version, and installs snapshots atomically; any fetch or
parse failure leaves the **last known-good** snapshot serving.

```go
loader := rbac.NewLoader(rbac.NewFileSource("/etc/app/policy.json"), rbac.DenyOverrides)
if err := loader.Refresh(ctx); err != nil {
    // fetch or parse failed — the loader keeps serving the last known-good snapshot
}
d := loader.Decide(q)
```

`NewFileSource` and `NewMemorySource` are reference sources; a real HTTP/git/blob source is a
drop-in `Source` implementation. Bundle integrity is an injectable `Verifier` (default no-op
pass-through) that runs before parse — a real signature check drops in via `WithVerifier`
without touching the engine.

## The trust contract (what you must guarantee)

The engine is total, deterministic, and fails closed **given trusted inputs** — it cannot
save an integration from untrusted ones. The obligations it can't enforce for itself:

- **Attribute provenance (load-bearing).** The engine trusts every `Grant` in `Query.Grants`
  equally and cannot detect a forged one — a `Grant` has no origin field. `Query.Grants` *is*
  the attribute bag; resolve it from a store keyed by a verified identity, **never** from
  request-controlled input. Laundering client-supplied grants into `Query.Grants` is the
  mistake to guard against.
- **Closed vocabulary.** The only comparison is string equality. No ordering/ranges, no
  numbers/time, no patterns (even `"*"` is a literal, not a wildcard), and only five attribute
  names exist (`need`, `scope`, `grant.cap`, `grant.scope`, `grant.effect`) — there is no
  `context` bag. Check what you need is expressible *before* designing a policy.
- **Absent is a non-match.** A missing attribute makes its comparison unknown (three-valued
  logic), a non-match against every value including `""`, distinct from present-empty. Missing
  data never grants access.
- **Fail-closed.** No snapshot → deny; a malformed/oversized bundle is rejected and the last
  known-good snapshot is kept; nothing opens or clears access.
- **Disclosure.** `Disclose(Minimal)` gives the caller a constant per-verdict string that
  leaks no structure; `Disclose(Full)` gives your own logs the complete rationale. Never send
  `Full` to the caller.
- **Flattening.** The engine has no hierarchy or prefix logic; any tree (org → dept → team,
  resource paths) must be flattened by the consumer into namespaced scopes before the call.

## Documentation & examples

The full integrator contract is the package documentation plus nine runnable, verified
examples:

```sh
go doc github.com/praetordev/rbac/v4      # the complete usage + trust contract
go test -run Example -v .                  # nine end-to-end examples
```

## Testing

Pure Go, no external services:

```sh
go test -race ./...
```

## Development & releases

CI (build, `go vet`, `gofmt`, `go test -race`) runs on every push and PR.

Releases are automatic on merge to `main` — the bump is derived from the **branch name
prefix**:

| Branch prefix | Bump  | Use for                           |
| ------------- | ----- | --------------------------------- |
| `debug/*`     | patch | bug fixes, no API change          |
| `feature/*`   | minor | backward-compatible additions     |
| `breaking/*`  | major | backward-incompatible API changes |

Merging any other prefix cuts no release. A release can also be cut on demand via the
`release` workflow's manual dispatch (`bump=patch|minor|major`).

Majors (v2+) require the module path to carry a `/vN` suffix
(`github.com/praetordev/rbac/v4`); land that module-path change in the same major PR, and the
release workflow verifies it before tagging.
