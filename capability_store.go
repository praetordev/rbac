package rbac

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/jmoiron/sqlx"
)

// CapabilityStore is the concrete Policy Decision Point behind the Authorizer
// interface: callers depend on Authorizer, this type answers via the two-tier
// capability SQL (a global NULL-scoped object role whose definition grants the
// codename, UNION a materialised role_evaluations row for the exact object).
//
// It assumes a fixed schema exists in the consumer's database:
//   - the capability tables — dab_permissions, role_definitions,
//     role_definition_permissions, object_roles, role_user_assignments,
//     role_team_assignments, role_evaluations — and the
//     rebuild_object_role_evaluations function;
//   - a team_members(team_id, user_id) membership table, joined to resolve a
//     team-granted role to its member users.
//
// It is agnostic only to WHICH resource types you protect: the "every id of
// content type X" lookup (the see-all tier) reads its table name from the
// injected content-type→table map. It is NOT agnostic to the capability schema
// or to team_members — this package owns the model but not its migrations, so
// the consumer must provision that schema (and the two libraries version in
// lockstep with it).
type CapabilityStore struct {
	db     *sqlx.DB
	tables map[ContentType]string
}

// NewCapabilityStore builds a CapabilityStore. tables maps each content type to
// the physical table AllIDsOfType lists ids from; the caller supplies it (and is
// responsible for the values being trusted table names, since they are
// interpolated into the query). A content type absent from the map cannot be
// enumerated by AllIDsOfType.
func NewCapabilityStore(db *sqlx.DB, tables map[ContentType]string) *CapabilityStore {
	return &CapabilityStore{db: db, tables: tables}
}

var _ Authorizer = (*CapabilityStore)(nil)

const roleDefinitionCols = `id, name, description, managed, content_type, created_at, modified_at`

// Can implements Authorizer: sub may perform action on obj, checked as the
// codename Codename(obj.Type, action). An action outside obj.Type's catalog is a
// programming error, surfaced as an error (→ 500) rather than a silent deny.
func (s *CapabilityStore) Can(ctx context.Context, sub Subject, action Action, obj Object) (bool, error) {
	if err := checkCapabilityDefined(obj.Type, action); err != nil {
		return false, wrap("CapabilityStore.Can", err)
	}
	return s.CanCodename(ctx, sub, Codename(obj.Type, action), obj)
}

// CanCodename implements Authorizer: sub holds an arbitrary codename on obj. The
// codename may name a different content type than obj (the cross-type
// create-in-container check), so it is not validated against obj.Type here.
func (s *CapabilityStore) CanCodename(ctx context.Context, sub Subject, codename string, obj Object) (bool, error) {
	return s.HasCapability(ctx, sub.UserID, obj.Type, obj.ID, codename)
}

// CanGlobal implements Authorizer: sub holds codename with global scope.
func (s *CapabilityStore) CanGlobal(ctx context.Context, sub Subject, codename string) (bool, error) {
	return s.HasGlobalCapability(ctx, sub.UserID, codename)
}

// VisibleIDs implements Authorizer: the object ids of t on which sub holds
// action, unifying the two tiers — a global grant of the codename sees every
// object of the type; otherwise the scoped (materialised) rows.
func (s *CapabilityStore) VisibleIDs(ctx context.Context, sub Subject, action Action, t ContentType) ([]int64, error) {
	codename := Codename(t, action)
	global, err := s.HasGlobalCapability(ctx, sub.UserID, codename)
	if err != nil {
		return nil, err
	}
	if global {
		return s.AllIDsOfType(ctx, t)
	}
	return s.AccessibleIDs(ctx, sub.UserID, t, codename)
}

// AllIDsOfType returns every object id of a content type — the global-tier answer
// for superusers and system auditors, who can see everything. The physical table
// comes from the injected content-type→table map.
func (s *CapabilityStore) AllIDsOfType(ctx context.Context, ct ContentType) ([]int64, error) {
	table, ok := s.tables[ct]
	if !ok {
		return nil, wrap("CapabilityStore.AllIDsOfType", fmt.Errorf("no table registered for content type %q", ct))
	}
	ids := []int64{}
	err := s.db.SelectContext(ctx, &ids, `SELECT id FROM `+table+` ORDER BY id`)
	return ids, wrap("CapabilityStore.AllIDsOfType", err)
}

// actorHolds is the SQL fragment (parameterised by $1 = user id) testing whether the
// current user holds the object_role aliased `orl` — directly, or via team membership.
const actorHolds = `(
	EXISTS (SELECT 1 FROM role_user_assignments ua WHERE ua.object_role_id = orl.id AND ua.user_id = $1)
	OR EXISTS (SELECT 1 FROM role_team_assignments ta
	           JOIN team_members tm ON tm.team_id = ta.team_id
	           WHERE ta.object_role_id = orl.id AND tm.user_id = $1)
)`

// HasCapability reports whether the user holds `codename` on (contentType, objectID),
// unifying two tiers: a GLOBAL object role whose definition grants the codename (system
// roles; no per-object rows), or a materialised evaluation row (scoped roles).
func (s *CapabilityStore) HasCapability(ctx context.Context, userID int64, contentType ContentType, objectID int64, codename string) (bool, error) {
	var ok bool
	err := s.db.GetContext(ctx, &ok, `
		SELECT EXISTS (
			-- global tier: a NULL-scoped object role whose definition grants the codename
			SELECT 1
			FROM object_roles orl
			JOIN role_definition_permissions rdp ON rdp.role_definition_id = orl.role_definition_id
			JOIN dab_permissions p ON p.id = rdp.permission_id
			WHERE orl.content_type IS NULL AND p.codename = $2 AND `+actorHolds+`
			UNION ALL
			-- scoped tier: a materialised evaluation row for this exact object
			SELECT 1
			FROM role_evaluations e
			JOIN object_roles orl ON orl.id = e.object_role_id
			WHERE e.content_type = $3 AND e.object_id = $4 AND e.codename = $2 AND `+actorHolds+`
		)`, userID, codename, string(contentType), objectID)
	return ok, wrap("CapabilityStore.HasCapability", err)
}

// HasGlobalCapability reports whether the user holds a global (system) role whose
// definition grants `codename` — the "see everything" tier for system roles.
func (s *CapabilityStore) HasGlobalCapability(ctx context.Context, userID int64, codename string) (bool, error) {
	var ok bool
	err := s.db.GetContext(ctx, &ok, `
		SELECT EXISTS (
			SELECT 1 FROM object_roles orl
			JOIN role_definition_permissions rdp ON rdp.role_definition_id = orl.role_definition_id
			JOIN dab_permissions p ON p.id = rdp.permission_id
			WHERE orl.content_type IS NULL AND p.codename = $2 AND `+actorHolds+`
		)`, userID, codename)
	return ok, wrap("CapabilityStore.HasGlobalCapability", err)
}

// AccessibleIDs returns the object ids of contentType on which the user holds `codename`
// via the scoped tier (materialised rows). The global tier (system roles) grants every
// object and is handled by the flag bypass during dual-run, so it is not expanded here.
func (s *CapabilityStore) AccessibleIDs(ctx context.Context, userID int64, contentType ContentType, codename string) ([]int64, error) {
	ids := []int64{}
	err := s.db.SelectContext(ctx, &ids, `
		SELECT DISTINCT e.object_id
		FROM role_evaluations e
		JOIN object_roles orl ON orl.id = e.object_role_id
		WHERE e.content_type = $2 AND e.codename = $3 AND `+actorHolds+`
		ORDER BY e.object_id`, userID, string(contentType), codename)
	return ids, wrap("CapabilityStore.AccessibleIDs", err)
}

// GetRoleDefinitionByName returns a single role definition by its unique name.
func (s *CapabilityStore) GetRoleDefinitionByName(ctx context.Context, name string) (RoleDefinition, error) {
	var d RoleDefinition
	err := s.db.GetContext(ctx, &d,
		`SELECT `+roleDefinitionCols+` FROM role_definitions WHERE name = $1`, name)
	return d, wrap("CapabilityStore.GetRoleDefinitionByName", err)
}

// getOrCreateObjectRole returns the id of the object_role for (definition, scope),
// creating it if absent. A nil contentType/objectID pair denotes a global (system)
// role. Runs in the given tx so it composes with assignment.
//
// Concurrency: two callers racing to create the same object_role are made safe by
// INSERT ... ON CONFLICT DO NOTHING plus a re-SELECT — the loser of the race reads
// the winner's row rather than failing on the unique violation. This requires the
// consumer's schema to carry a unique constraint on the scope: a plain unique index
// on (role_definition_id, content_type, object_id) for scoped roles, and a PARTIAL
// unique index on (role_definition_id) WHERE content_type IS NULL for the global
// scope (a plain index does not dedupe NULLs). Without those constraints the
// ON CONFLICT never fires and concurrent inserts can still duplicate.
func getOrCreateObjectRole(ctx context.Context, tx *sqlx.Tx, defID int64, contentType *string, objectID *int64) (int64, error) {
	// Global vs scoped are distinguished so the NULL-scope lookup matches correctly
	// (NULL = NULL is never true in a plain equality).
	var selectQuery, insertQuery string
	var args []any
	if contentType == nil {
		selectQuery = `SELECT id FROM object_roles WHERE role_definition_id = $1 AND content_type IS NULL`
		insertQuery = `INSERT INTO object_roles (role_definition_id, content_type, object_id) VALUES ($1, NULL, NULL) ON CONFLICT DO NOTHING RETURNING id`
		args = []any{defID}
	} else {
		selectQuery = `SELECT id FROM object_roles WHERE role_definition_id = $1 AND content_type = $2 AND object_id = $3`
		insertQuery = `INSERT INTO object_roles (role_definition_id, content_type, object_id) VALUES ($1, $2, $3) ON CONFLICT DO NOTHING RETURNING id`
		args = []any{defID, *contentType, *objectID}
	}

	var id int64
	// Fast path: the object_role already exists.
	err := tx.GetContext(ctx, &id, selectQuery, args...)
	if err == nil {
		return id, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return 0, err // a real error (conn reset, cancelled, ...) — do not mistake it for "absent".
	}

	// Absent: create it. ON CONFLICT DO NOTHING RETURNING yields a row only if we won
	// the insert; a concurrent inserter makes it return no rows (sql.ErrNoRows).
	err = tx.GetContext(ctx, &id, insertQuery, args...)
	if err == nil {
		return id, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return 0, err
	}

	// Lost the race: the row now exists (committed by the concurrent inserter, which
	// this statement blocked on). Re-read it.
	err = tx.GetContext(ctx, &id, selectQuery, args...)
	return id, err
}

// GiveUserPermission assigns a user the role definition scoped to (contentType, objectID)
// — nil/nil for a global role — and refreshes the evaluation cache. Idempotent.
func (s *CapabilityStore) GiveUserPermission(ctx context.Context, defID int64, contentType *string, objectID *int64, userID int64) error {
	err := runInTx(ctx, s.db, func(tx *sqlx.Tx) error {
		orID, err := getOrCreateObjectRole(ctx, tx, defID, contentType, objectID)
		if err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO role_user_assignments (role_definition_id, user_id, object_role_id)
			VALUES ($1, $2, $3) ON CONFLICT (user_id, object_role_id) DO NOTHING`, defID, userID, orID); err != nil {
			return err
		}
		_, err = tx.ExecContext(ctx, `SELECT rebuild_object_role_evaluations($1)`, orID)
		return err
	})
	return wrap("CapabilityStore.GiveUserPermission", err)
}

// GiveTeamPermission is GiveUserPermission for a team.
func (s *CapabilityStore) GiveTeamPermission(ctx context.Context, defID int64, contentType *string, objectID *int64, teamID int64) error {
	err := runInTx(ctx, s.db, func(tx *sqlx.Tx) error {
		orID, err := getOrCreateObjectRole(ctx, tx, defID, contentType, objectID)
		if err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO role_team_assignments (role_definition_id, team_id, object_role_id)
			VALUES ($1, $2, $3) ON CONFLICT (team_id, object_role_id) DO NOTHING`, defID, teamID, orID); err != nil {
			return err
		}
		_, err = tx.ExecContext(ctx, `SELECT rebuild_object_role_evaluations($1)`, orID)
		return err
	})
	return wrap("CapabilityStore.GiveTeamPermission", err)
}

// AssignableRoles returns the RoleDefinitions that can be granted on an object of the
// given content type: the managed roles scoped to that type, plus any custom (unscoped or
// matching) definitions.
func (s *CapabilityStore) AssignableRoles(ctx context.Context, contentType string) ([]RoleDefinition, error) {
	defs := []RoleDefinition{}
	err := s.db.SelectContext(ctx, &defs,
		`SELECT `+roleDefinitionCols+` FROM role_definitions
		 WHERE content_type = $1 OR (managed = false AND content_type IS NULL)
		 ORDER BY managed DESC, name`, contentType)
	return defs, wrap("CapabilityStore.AssignableRoles", err)
}

// RevokeUserPermission removes a user's assignment of a definition scoped to an object.
func (s *CapabilityStore) RevokeUserPermission(ctx context.Context, defID int64, contentType string, objectID, userID int64) error {
	_, err := s.db.ExecContext(ctx, `
		DELETE FROM role_user_assignments ua USING object_roles orl
		WHERE ua.object_role_id = orl.id AND ua.user_id = $1
		  AND orl.role_definition_id = $2 AND orl.content_type = $3 AND orl.object_id = $4`,
		userID, defID, contentType, objectID)
	return wrap("CapabilityStore.RevokeUserPermission", err)
}

// RevokeTeamPermission removes a team's assignment of a definition scoped to an object.
func (s *CapabilityStore) RevokeTeamPermission(ctx context.Context, defID int64, contentType string, objectID, teamID int64) error {
	_, err := s.db.ExecContext(ctx, `
		DELETE FROM role_team_assignments ta USING object_roles orl
		WHERE ta.object_role_id = orl.id AND ta.team_id = $1
		  AND orl.role_definition_id = $2 AND orl.content_type = $3 AND orl.object_id = $4`,
		teamID, defID, contentType, objectID)
	return wrap("CapabilityStore.RevokeTeamPermission", err)
}

// wrap annotates a store error with the operation that produced it; nil-safe and
// uses %w so callers' errors.Is / errors.As keep working through it.
func wrap(op string, err error) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("%s: %w", op, err)
}

// runInTx runs fn inside a transaction, committing on success and rolling back on any
// error (or panic).
func runInTx(ctx context.Context, db *sqlx.DB, fn func(tx *sqlx.Tx) error) error {
	tx, err := db.BeginTxx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()
	if err := fn(tx); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}
	return nil
}
