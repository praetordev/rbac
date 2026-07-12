# rbac

AWX/DAB-style capability RBAC for Praetor: the capability catalog, managed role
definitions, and the `Authorizer` policy-decision-point contract that Praetor's
services enforce against.

```go
import "github.com/praetordev/rbac"
```

## Development & releases

CI (build, `go vet`, `gofmt`, `go test -race`) runs on every push and PR.

Releases are automatic on merge to `main` — the version bump is derived from the
**branch name prefix**:

| Branch prefix | Bump  | Example              | Use for                              |
| ------------- | ----- | -------------------- | ------------------------------------ |
| `debug/*`     | patch | `v0.2.0 → v0.2.1`    | bug fixes, no API change             |
| `feature/*`   | minor | `v0.2.0 → v0.3.0`    | backward-compatible additions        |
| `breaking/*`  | major | `v0.2.0 → v1.0.0`    | backward-incompatible API changes    |

Merging a branch with any other prefix cuts no release.

Flow: branch (`feature/my-thing`) → open a PR into `main` → merge. The
[release workflow](.github/workflows/release.yml) validates, computes the next
SemVer tag from the latest existing tag, creates the annotated tag and a GitHub
Release. The Go module proxy serves it — no separate publish step.

> **Major versions ≥ v2:** Go requires the module path to carry a `/vN` suffix
> (`github.com/praetordev/rbac/v2`). The release workflow deliberately refuses to
> auto-tag those; do the module-path migration in a PR and tag it manually.
