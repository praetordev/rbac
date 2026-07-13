package rbac

import (
	"context"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/jmoiron/sqlx"
	_ "github.com/lib/pq"
)

// Integration tests for the CapabilityStore PDP. They require a real Postgres
// (the store speaks Postgres-specific SQL — partial indexes, ON CONFLICT), so
// they are gated on RBAC_TEST_DATABASE_URL and skip when it is unset.
//
//   RBAC_TEST_DATABASE_URL='postgres://user:pass@localhost:5432/rbac_test?sslmode=disable' go test ./...
//
// Each test provisions its own fixture in a throwaway state (dropObjects + testSchema),
// so the target database may be any scratch database — the tests own their tables.
//
// Scope: these exercise the query-time decision path (HasCapability / HasGlobalCapability /
// VisibleIDs) and the assignment write path (Give*/Revoke*). The fixture's
// rebuild_object_role_evaluations is a NO-OP STUB — the real one (org->child propagation)
// lives in the consumer's migrations and is that repo's to test. Scoped read tests
// therefore materialise role_evaluations rows directly, which is exactly what lets the
// revoke test prove the safety property without depending on propagation.

// testSchema is a minimal but faithful subset of the consumer's capability schema
// (praetor migration 000056), carrying the columns, the CHECK, and — critically — the
// two partial unique indexes the store's ON CONFLICT relies on. Parent-table foreign
// keys (users/teams) are intentionally dropped so the fixture stands alone.
const testSchema = `
CREATE TABLE role_definitions (
    id BIGSERIAL PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    description TEXT NOT NULL DEFAULT '',
    managed BOOLEAN NOT NULL DEFAULT false,
    content_type TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    modified_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TABLE dab_permissions (
    id BIGSERIAL PRIMARY KEY,
    codename TEXT NOT NULL UNIQUE,
    content_type TEXT NOT NULL,
    action TEXT NOT NULL
);
CREATE TABLE role_definition_permissions (
    role_definition_id BIGINT NOT NULL REFERENCES role_definitions(id) ON DELETE CASCADE,
    permission_id BIGINT NOT NULL REFERENCES dab_permissions(id) ON DELETE CASCADE,
    PRIMARY KEY (role_definition_id, permission_id)
);
CREATE TABLE object_roles (
    id BIGSERIAL PRIMARY KEY,
    role_definition_id BIGINT NOT NULL REFERENCES role_definitions(id) ON DELETE CASCADE,
    content_type TEXT,
    object_id BIGINT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CHECK ((content_type IS NULL) = (object_id IS NULL))
);
CREATE UNIQUE INDEX uq_object_roles_scoped ON object_roles (role_definition_id, content_type, object_id) WHERE content_type IS NOT NULL;
CREATE UNIQUE INDEX uq_object_roles_global ON object_roles (role_definition_id) WHERE content_type IS NULL;
CREATE TABLE role_user_assignments (
    id BIGSERIAL PRIMARY KEY,
    role_definition_id BIGINT NOT NULL REFERENCES role_definitions(id) ON DELETE CASCADE,
    user_id BIGINT NOT NULL,
    object_role_id BIGINT NOT NULL REFERENCES object_roles(id) ON DELETE CASCADE,
    UNIQUE (user_id, object_role_id)
);
CREATE TABLE role_team_assignments (
    id BIGSERIAL PRIMARY KEY,
    role_definition_id BIGINT NOT NULL REFERENCES role_definitions(id) ON DELETE CASCADE,
    team_id BIGINT NOT NULL,
    object_role_id BIGINT NOT NULL REFERENCES object_roles(id) ON DELETE CASCADE,
    UNIQUE (team_id, object_role_id)
);
CREATE TABLE role_evaluations (
    object_role_id BIGINT NOT NULL REFERENCES object_roles(id) ON DELETE CASCADE,
    content_type TEXT NOT NULL,
    object_id BIGINT NOT NULL,
    codename TEXT NOT NULL,
    PRIMARY KEY (object_role_id, content_type, object_id, codename)
);
CREATE TABLE team_members (
    team_id BIGINT NOT NULL,
    user_id BIGINT NOT NULL,
    PRIMARY KEY (team_id, user_id)
);
CREATE TABLE inventories (id BIGINT PRIMARY KEY);
-- Test stub only: the real function does org->child propagation and lives in the
-- consumer's migrations. Here it is a no-op so Give*/Revoke* run end to end.
CREATE FUNCTION rebuild_object_role_evaluations(p_or_id BIGINT) RETURNS VOID AS $$ BEGIN RETURN; END; $$ LANGUAGE plpgsql;
`

const dropObjects = `
DROP FUNCTION IF EXISTS rebuild_object_role_evaluations(BIGINT);
DROP TABLE IF EXISTS inventories, team_members, role_evaluations, role_team_assignments,
    role_user_assignments, object_roles, role_definition_permissions, dab_permissions,
    role_definitions CASCADE;
`

// testInventoryTables is the content-type->table map for AllIDsOfType in tests.
var testInventoryTables = map[ContentType]string{ContentTypeInventory: "inventories"}

// newTestStore connects to RBAC_TEST_DATABASE_URL (skipping if unset), reprovisions
// the fixture from scratch, and returns a store plus the raw handle for seeding.
func newTestStore(t *testing.T) (*CapabilityStore, *sqlx.DB) {
	t.Helper()
	dsn := os.Getenv("RBAC_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("RBAC_TEST_DATABASE_URL not set; skipping Postgres integration test")
	}
	db, err := sqlx.Connect("postgres", dsn)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	if _, err := db.Exec(dropObjects); err != nil {
		t.Fatalf("drop fixture: %v", err)
	}
	if _, err := db.Exec(testSchema); err != nil {
		t.Fatalf("create fixture: %v", err)
	}
	return NewCapabilityStore(db, testInventoryTables), db
}

// --- seed helpers ---------------------------------------------------------------

func mustGetID(t *testing.T, db *sqlx.DB, query string, args ...any) int64 {
	t.Helper()
	var id int64
	if err := db.Get(&id, query, args...); err != nil {
		t.Fatalf("seed %q: %v", query, err)
	}
	return id
}

func mustExec(t *testing.T, db *sqlx.DB, query string, args ...any) {
	t.Helper()
	if _, err := db.Exec(query, args...); err != nil {
		t.Fatalf("seed %q: %v", query, err)
	}
}

// seedDefWithPerm creates a role definition (contentType nil => global) granting a single
// capability codename, and returns the definition id.
func seedDefWithPerm(t *testing.T, db *sqlx.DB, name string, contentType *string, codename, permCT, action string) int64 {
	t.Helper()
	defID := mustGetID(t, db,
		`INSERT INTO role_definitions (name, content_type) VALUES ($1, $2) RETURNING id`, name, contentType)
	permID := mustGetID(t, db,
		`INSERT INTO dab_permissions (codename, content_type, action) VALUES ($1, $2, $3) RETURNING id`, codename, permCT, action)
	mustExec(t, db,
		`INSERT INTO role_definition_permissions (role_definition_id, permission_id) VALUES ($1, $2)`, defID, permID)
	return defID
}

func seedObjectRole(t *testing.T, db *sqlx.DB, defID int64, contentType *string, objectID *int64) int64 {
	t.Helper()
	return mustGetID(t, db,
		`INSERT INTO object_roles (role_definition_id, content_type, object_id) VALUES ($1, $2, $3) RETURNING id`,
		defID, contentType, objectID)
}

func str(s string) *string { return &s }
func i64(n int64) *int64   { return &n }

// --- tests ----------------------------------------------------------------------

// TestHasCapability_TwoTier covers both arms of the HasCapability UNION: a global
// (NULL-scoped) role grants the codename on any object; a scoped role grants it only on
// the object with a materialised evaluation row.
func TestHasCapability_TwoTier(t *testing.T) {
	ctx := context.Background()
	s, db := newTestStore(t)

	// Global tier: System Administrator holds manage_organization everywhere.
	gDef := seedDefWithPerm(t, db, "System Administrator", nil, "manage_organization", "organization", "manage")
	gOR := seedObjectRole(t, db, gDef, nil, nil)
	mustExec(t, db, `INSERT INTO role_user_assignments (role_definition_id, user_id, object_role_id) VALUES ($1, $2, $3)`, gDef, 1, gOR)

	// Scoped tier: Inventory Admin on inventory 42 only.
	sDef := seedDefWithPerm(t, db, "Inventory Admin", str("inventory"), "change_inventory", "inventory", "change")
	sOR := seedObjectRole(t, db, sDef, str("inventory"), i64(42))
	mustExec(t, db, `INSERT INTO role_evaluations (object_role_id, content_type, object_id, codename) VALUES ($1, 'inventory', 42, 'change_inventory')`, sOR)
	mustExec(t, db, `INSERT INTO role_user_assignments (role_definition_id, user_id, object_role_id) VALUES ($1, $2, $3)`, sDef, 2, sOR)

	cases := []struct {
		name   string
		user   int64
		ct     ContentType
		obj    int64
		code   string
		expect bool
	}{
		{"global holder sees any org", 1, ContentTypeOrganization, 7, "manage_organization", true},
		{"global holder sees another org", 1, ContentTypeOrganization, 99, "manage_organization", true},
		{"non-holder denied global", 2, ContentTypeOrganization, 7, "manage_organization", false},
		{"scoped holder on granted object", 2, ContentTypeInventory, 42, "change_inventory", true},
		{"scoped holder on other object", 2, ContentTypeInventory, 43, "change_inventory", false},
		{"non-holder denied scoped", 1, ContentTypeInventory, 42, "change_inventory", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := s.HasCapability(ctx, tc.user, tc.ct, tc.obj, tc.code)
			if err != nil {
				t.Fatalf("HasCapability: %v", err)
			}
			if got != tc.expect {
				t.Fatalf("HasCapability(u=%d,%s,%d,%s) = %v, want %v", tc.user, tc.ct, tc.obj, tc.code, got, tc.expect)
			}
		})
	}
}

// TestRevokeTakesEffectImmediately is the headline safety property (Fable concern #1):
// role_evaluations rows are keyed by object_role and actorHolds joins assignments live, so
// deleting the assignment denies access on the very next check — with NO cache rebuild.
// A regression that cached membership into role_evaluations would fail this test.
func TestRevokeTakesEffectImmediately(t *testing.T) {
	ctx := context.Background()
	s, db := newTestStore(t)

	defID := seedDefWithPerm(t, db, "Inventory Admin", str("inventory"), "change_inventory", "inventory", "change")
	orID := seedObjectRole(t, db, defID, str("inventory"), i64(42))
	mustExec(t, db, `INSERT INTO role_evaluations (object_role_id, content_type, object_id, codename) VALUES ($1, 'inventory', 42, 'change_inventory')`, orID)
	mustExec(t, db, `INSERT INTO role_user_assignments (role_definition_id, user_id, object_role_id) VALUES ($1, $2, $3)`, defID, 7, orID)

	before, err := s.HasCapability(ctx, 7, ContentTypeInventory, 42, "change_inventory")
	if err != nil {
		t.Fatalf("HasCapability before: %v", err)
	}
	if !before {
		t.Fatal("expected access before revoke")
	}

	if err := s.RevokeUserPermission(ctx, defID, "inventory", 42, 7); err != nil {
		t.Fatalf("RevokeUserPermission: %v", err)
	}

	// The evaluation row must still exist — revoke deletes only the assignment, never
	// rebuilds. This is the invariant that makes omitting the rebuild safe.
	var evalRows int
	if err := db.Get(&evalRows, `SELECT count(*) FROM role_evaluations WHERE object_role_id = $1`, orID); err != nil {
		t.Fatalf("count evals: %v", err)
	}
	if evalRows != 1 {
		t.Fatalf("expected evaluation row to persist through revoke, got %d rows", evalRows)
	}

	after, err := s.HasCapability(ctx, 7, ContentTypeInventory, 42, "change_inventory")
	if err != nil {
		t.Fatalf("HasCapability after: %v", err)
	}
	if after {
		t.Fatal("expected access to be denied immediately after revoke")
	}
}

// TestGiveUserPermission_Idempotent exercises getOrCreateObjectRole (issue #122): repeated
// grants must reuse the one object_role (scoped and global), not duplicate it, and a second
// user on the same scope shares it.
func TestGiveUserPermission_Idempotent(t *testing.T) {
	ctx := context.Background()
	s, db := newTestStore(t)

	// Scoped: two grants for user 1, one for user 2, all on (inventory, 42).
	sDef := seedDefWithPerm(t, db, "Inventory Admin", str("inventory"), "change_inventory", "inventory", "change")
	for i := 0; i < 2; i++ {
		if err := s.GiveUserPermission(ctx, sDef, str("inventory"), i64(42), 1); err != nil {
			t.Fatalf("GiveUserPermission user1 #%d: %v", i, err)
		}
	}
	if err := s.GiveUserPermission(ctx, sDef, str("inventory"), i64(42), 2); err != nil {
		t.Fatalf("GiveUserPermission user2: %v", err)
	}

	var scopedORs int
	mustGet(t, db, &scopedORs, `SELECT count(*) FROM object_roles WHERE role_definition_id = $1 AND content_type = 'inventory' AND object_id = 42`, sDef)
	if scopedORs != 1 {
		t.Fatalf("expected exactly 1 scoped object_role, got %d", scopedORs)
	}
	var assignments int
	mustGet(t, db, &assignments, `SELECT count(*) FROM role_user_assignments ua JOIN object_roles orl ON orl.id = ua.object_role_id WHERE orl.role_definition_id = $1 AND orl.object_id = 42`, sDef)
	if assignments != 2 {
		t.Fatalf("expected 2 assignments, got %d", assignments)
	}

	// Global: two grants must dedupe to one NULL-scoped object_role via the partial index.
	gDef := seedDefWithPerm(t, db, "System Administrator", nil, "manage_organization", "organization", "manage")
	for i := 0; i < 2; i++ {
		if err := s.GiveUserPermission(ctx, gDef, nil, nil, 1); err != nil {
			t.Fatalf("GiveUserPermission global #%d: %v", i, err)
		}
	}
	var globalORs int
	mustGet(t, db, &globalORs, `SELECT count(*) FROM object_roles WHERE role_definition_id = $1 AND content_type IS NULL`, gDef)
	if globalORs != 1 {
		t.Fatalf("expected exactly 1 global object_role, got %d", globalORs)
	}
}

// TestGiveUserPermission_ConcurrentSameScope is the TOCTOU proof for issue #122: many
// goroutines grant the same (definition, object) scope at once with no pre-existing
// object_role, so they race inside getOrCreateObjectRole. The ON CONFLICT DO NOTHING +
// re-SELECT must converge them onto exactly one object_role with no errors. Before the
// fix (plain SELECT-then-INSERT) this would either duplicate the object_role or fail one
// grant on the unique-index violation.
func TestGiveUserPermission_ConcurrentSameScope(t *testing.T) {
	ctx := context.Background()
	s, db := newTestStore(t)
	defID := seedDefWithPerm(t, db, "Inventory Admin", str("inventory"), "change_inventory", "inventory", "change")

	const n = 12
	errs := make(chan error, n)
	start := make(chan struct{})
	var wg sync.WaitGroup
	for u := 0; u < n; u++ {
		wg.Add(1)
		go func(userID int64) {
			defer wg.Done()
			<-start // release all goroutines together to maximise contention
			errs <- s.GiveUserPermission(ctx, defID, str("inventory"), i64(42), userID)
		}(int64(u + 1))
	}
	close(start)
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("concurrent GiveUserPermission: %v", err)
		}
	}

	var objectRoles int
	mustGet(t, db, &objectRoles, `SELECT count(*) FROM object_roles WHERE role_definition_id = $1 AND content_type = 'inventory' AND object_id = 42`, defID)
	if objectRoles != 1 {
		t.Fatalf("expected exactly 1 object_role after %d concurrent grants, got %d", n, objectRoles)
	}
	var assignments int
	mustGet(t, db, &assignments, `SELECT count(*) FROM role_user_assignments ua JOIN object_roles orl ON orl.id = ua.object_role_id WHERE orl.role_definition_id = $1 AND orl.object_id = 42`, defID)
	if assignments != n {
		t.Fatalf("expected %d assignments, got %d", n, assignments)
	}
}

// TestGetOrCreateObjectRole_LoserReSelects deterministically drives the ON CONFLICT +
// re-SELECT branch of the fix (issue #122), which the probabilistic stress test above
// cannot reliably reach. Two transactions race for the same scope: the winner (tx1)
// inserts but holds its transaction open; the loser (tx2) misses on its SELECT and blocks
// on the unique-index entry inside its INSERT. Only once tx2 is provably blocked do we
// commit tx1 — forcing tx2's ON CONFLICT DO NOTHING to return no rows and fall through to
// the re-SELECT, which must return the winner's id with no error. Against the pre-fix
// plain INSERT, tx2 would instead raise a unique_violation.
func TestGetOrCreateObjectRole_LoserReSelects(t *testing.T) {
	ctx := context.Background()
	_, db := newTestStore(t)
	defID := seedDefWithPerm(t, db, "Inventory Admin", str("inventory"), "change_inventory", "inventory", "change")

	// Winner: create the object_role in tx1 but do not commit yet.
	tx1, err := db.BeginTxx(ctx, nil)
	if err != nil {
		t.Fatalf("begin tx1: %v", err)
	}
	id1, err := getOrCreateObjectRole(ctx, tx1, defID, str("inventory"), i64(42))
	if err != nil {
		tx1.Rollback()
		t.Fatalf("winner getOrCreateObjectRole: %v", err)
	}

	// Loser: races for the same scope in tx2; its INSERT blocks on tx1's index entry.
	type result struct {
		id  int64
		err error
	}
	done := make(chan result, 1)
	go func() {
		tx2, err := db.BeginTxx(ctx, nil)
		if err != nil {
			done <- result{0, err}
			return
		}
		id2, err := getOrCreateObjectRole(ctx, tx2, defID, str("inventory"), i64(42))
		if err != nil {
			tx2.Rollback()
			done <- result{0, err}
			return
		}
		done <- result{id2, tx2.Commit()}
	}()

	// Release tx1 only once tx2 is actually blocked on the object_roles insert lock.
	waitForBlockedOn(t, db, "object_roles")
	if err := tx1.Commit(); err != nil {
		t.Fatalf("commit tx1: %v", err)
	}

	r := <-done
	if r.err != nil {
		t.Fatalf("loser errored instead of re-selecting the winner's row: %v", r.err)
	}
	if r.id != id1 {
		t.Fatalf("loser got object_role id %d, want winner's %d", r.id, id1)
	}
	var count int
	mustGet(t, db, &count, `SELECT count(*) FROM object_roles WHERE role_definition_id = $1 AND object_id = 42`, defID)
	if count != 1 {
		t.Fatalf("expected exactly 1 object_role after the race, got %d", count)
	}
}

// waitForBlockedOn blocks until at least one backend is waiting on a lock while running a
// query mentioning needle, so a test can order two transactions without a fixed sleep.
func waitForBlockedOn(t *testing.T, db *sqlx.DB, needle string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		var n int
		if err := db.Get(&n,
			`SELECT count(*) FROM pg_stat_activity
			 WHERE wait_event_type = 'Lock' AND state = 'active' AND query LIKE '%' || $1 || '%'`, needle); err != nil {
			t.Fatalf("poll pg_stat_activity: %v", err)
		}
		if n >= 1 {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("timed out waiting for the loser transaction to block on the insert lock")
}

// TestVisibleIDs_GlobalVsScoped covers the two-tier list path: a global grant sees every
// id of the type (AllIDsOfType), a scoped grant sees only its materialised objects.
func TestVisibleIDs_GlobalVsScoped(t *testing.T) {
	ctx := context.Background()
	s, db := newTestStore(t)
	for _, id := range []int64{42, 43, 44} {
		mustExec(t, db, `INSERT INTO inventories (id) VALUES ($1)`, id)
	}

	// Global viewer.
	gDef := seedDefWithPerm(t, db, "System Auditor", nil, "view_inventory", "inventory", "view")
	gOR := seedObjectRole(t, db, gDef, nil, nil)
	mustExec(t, db, `INSERT INTO role_user_assignments (role_definition_id, user_id, object_role_id) VALUES ($1, $2, $3)`, gDef, 1, gOR)

	// Scoped viewer: inventory 43 only.
	sDef := seedDefWithPerm(t, db, "Inventory Reader", str("inventory"), "view_inventory_scoped_placeholder", "inventory", "view")
	// Reuse the canonical codename for the scoped eval row (definitions can share a codename).
	sOR := seedObjectRole(t, db, sDef, str("inventory"), i64(43))
	mustExec(t, db, `INSERT INTO role_evaluations (object_role_id, content_type, object_id, codename) VALUES ($1, 'inventory', 43, 'view_inventory')`, sOR)
	mustExec(t, db, `INSERT INTO role_user_assignments (role_definition_id, user_id, object_role_id) VALUES ($1, $2, $3)`, sDef, 2, sOR)

	globalIDs, err := s.VisibleIDs(ctx, Subject{UserID: 1}, ActionView, ContentTypeInventory)
	if err != nil {
		t.Fatalf("VisibleIDs global: %v", err)
	}
	if !equalInts(globalIDs, []int64{42, 43, 44}) {
		t.Fatalf("global VisibleIDs = %v, want [42 43 44]", globalIDs)
	}

	scopedIDs, err := s.VisibleIDs(ctx, Subject{UserID: 2}, ActionView, ContentTypeInventory)
	if err != nil {
		t.Fatalf("VisibleIDs scoped: %v", err)
	}
	if !equalInts(scopedIDs, []int64{43}) {
		t.Fatalf("scoped VisibleIDs = %v, want [43]", scopedIDs)
	}
}

func mustGet(t *testing.T, db *sqlx.DB, dest any, query string, args ...any) {
	t.Helper()
	if err := db.Get(dest, query, args...); err != nil {
		t.Fatalf("query %q: %v", query, err)
	}
}

func equalInts(a, b []int64) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
