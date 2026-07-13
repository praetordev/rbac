# rbac

A generic, capability-based Role-Based Access Control engine for Go.

It provides the **mechanism** — the `Authorizer` decision contract and the
capability/role model — with **no built-in vocabulary**. A consumer declares its own
content types, actions, and roles by building a `Catalog`; the engine hardcodes none
of them.

## Layout

| Package | Import | Role |
| ------- | ------ | ---- |
| `rbac` | `github.com/praetordev/rbac/v3` | the `Authorizer` contract, `Catalog`, and the model — **pure Go, no database dependency** |
| `postgres` | `github.com/praetordev/rbac/v3/postgres` | the Postgres-backed `Store` (the PDP) |

A different backend is a drop-in `rbac.Authorizer` implementation; consumers of the
contract never pull `sqlx`.

## Usage

Declare a vocabulary and wire a store:

```go
import (
    rbac "github.com/praetordev/rbac/v3"
    "github.com/praetordev/rbac/v3/postgres"
)

cat := rbac.NewCatalog().
    Type("project", "view", "change", "manage").
    Type("inventory", "view", "change", "use").
    System("manage_user", "user", "manage", "Manage users") // global-scope-only

store, err := postgres.NewStore(postgres.Config{
    DB:               db,      // *sqlx.DB against the capability schema
    Catalog:          cat,
    Tables:           map[rbac.ContentType]string{"project": "projects", "inventory": "inventories"},
    TeamMembersTable: "team_members", // injected; defaults to "team_members"
})

var authz rbac.Authorizer = store

ok, err := authz.Can(ctx, rbac.NewSubject(userID), "change", rbac.Obj("project", 42))
ids, err := authz.VisibleIDs(ctx, rbac.NewSubject(userID), "view", "inventory")
```

Callers depend on the `Authorizer` interface, never on the concrete store. Every
decision is **deny-by-default** and returns an error on infrastructure failure, so a
database problem surfaces as a 500 rather than a silent allow.

## Schema

The engine owns the capability **model** but not its migrations. The consumer must
provision the schema it queries — `dab_permissions`, `role_definitions`,
`role_definition_permissions`, `object_roles`, `role_user_assignments`,
`role_team_assignments`, `role_evaluations`, the membership table, and the
`rebuild_object_role_evaluations` function — and version it alongside this library.
Seed `dab_permissions` from `catalog.Permissions()` and `catalog.SystemPermissions()`.

`object_roles` must carry a unique index on `(role_definition_id, content_type,
object_id)` and a **partial** unique index on `(role_definition_id) WHERE content_type
IS NULL`, which the store's concurrency-safe grant path relies on.

## Testing

The store's integration tests require a real Postgres and are gated on
`RBAC_TEST_DATABASE_URL`; without it they skip.

```sh
RBAC_TEST_DATABASE_URL='postgres://user:pass@localhost:5432/rbac_test?sslmode=disable' go test -race ./...
```

## Development & releases

CI (build, `go vet`, `gofmt`, `go test -race`) runs on every push and PR.

Releases are automatic on merge to `main` — the bump is derived from the **branch
name prefix**:

| Branch prefix | Bump  | Use for                           |
| ------------- | ----- | --------------------------------- |
| `debug/*`     | patch | bug fixes, no API change          |
| `feature/*`   | minor | backward-compatible additions     |
| `breaking/*`  | major | backward-incompatible API changes |

Merging any other prefix cuts no release. A release can also be cut on demand via the
`release` workflow's manual dispatch (`bump=patch|minor|major`).

Majors (v2+) require the module path to carry a `/vN` suffix
(`github.com/praetordev/rbac/v3`); land that module-path change in the same major PR,
and the release workflow verifies it before tagging.
