// Package postgres is the Postgres-backed policy decision point for the rbac engine.
//
// Store implements rbac.Authorizer over a fixed capability schema using
// Postgres-specific SQL (partial unique indexes, ON CONFLICT). It is the one place
// the engine touches a database; the root rbac package stays free of any I/O
// dependency, so a different backend is a drop-in rbac.Authorizer implementation.
package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"regexp"

	"github.com/jmoiron/sqlx"

	rbac "github.com/praetordev/rbac/v3"
)

// Store is the concrete Policy Decision Point behind rbac.Authorizer: callers depend
// on the interface, this type answers via the two-tier capability SQL (a global
// NULL-scoped object role whose definition grants the codename, UNION a materialised
// role_evaluations row for the exact object).
//
// It assumes a fixed capability schema exists in the consumer's database —
// dab_permissions, role_definitions, role_definition_permissions, object_roles,
// role_user_assignments, role_team_assignments, role_evaluations, the membership
// table, and the rebuild_object_role_evaluations function. The engine owns the model
// but not its migrations, so the consumer provisions that schema and the two version
// together. Everything domain-specific — the content types, the resource tables, the
// membership table name — is injected via Config; the engine hardcodes none of it.
type Store struct {
	db         *sqlx.DB
	catalog    *rbac.Catalog
	tables     map[rbac.ContentType]string
	actorHolds string
}

// Config wires a Store to a consumer's database and vocabulary.
type Config struct {
	// DB is the capability-schema database handle. Required.
	DB *sqlx.DB
	// Catalog is the consumer's capability vocabulary, used to validate Can requests.
	// Required.
	Catalog *rbac.Catalog
	// Tables maps each content type to the physical table AllIDsOfType enumerates ids
	// from (the "see all" tier for global grants). A content type absent from the map
	// cannot be enumerated. Values must be valid, trusted SQL identifiers — they are
	// interpolated into queries — and are validated at construction.
	Tables map[rbac.ContentType]string
	// TeamMembersTable is the (team_id, user_id) membership table joined to resolve a
	// team-granted role to its member users. Defaults to "team_members". Validated as a
	// SQL identifier.
	TeamMembersTable string
}

var identifierRE = regexp.MustCompile(`^[a-z_][a-z0-9_]*$`)

// safeIdentifier reports whether s is a plain lower-snake SQL identifier, safe to
// interpolate into a query. It deliberately excludes schema-qualified names and quoting.
func safeIdentifier(s string) bool { return identifierRE.MatchString(s) }

// actorHoldsTemplate is the SQL fragment (parameterised by $1 = user id) testing whether
// the current user holds the object_role aliased `orl` — directly, or via team
// membership. %s is the consumer's membership table.
const actorHoldsTemplate = `(
	EXISTS (SELECT 1 FROM role_user_assignments ua WHERE ua.object_role_id = orl.id AND ua.user_id = $1)
	OR EXISTS (SELECT 1 FROM role_team_assignments ta
	           JOIN %s tm ON tm.team_id = ta.team_id
	           WHERE ta.object_role_id = orl.id AND tm.user_id = $1)
)`

// NewStore builds a Store from cfg, validating that every injected table name is a plain
// SQL identifier so the interpolations in AllIDsOfType and the membership join are safe by
// construction. It returns an error for missing required fields or an unsafe identifier.
func NewStore(cfg Config) (*Store, error) {
	if cfg.DB == nil {
		return nil, fmt.Errorf("postgres.NewStore: Config.DB is required")
	}
	if cfg.Catalog == nil {
		return nil, fmt.Errorf("postgres.NewStore: Config.Catalog is required")
	}
	members := cfg.TeamMembersTable
	if members == "" {
		members = "team_members"
	}
	if !safeIdentifier(members) {
		return nil, fmt.Errorf("postgres.NewStore: TeamMembersTable %q is not a valid SQL identifier", members)
	}
	tables := make(map[rbac.ContentType]string, len(cfg.Tables))
	for ct, tbl := range cfg.Tables {
		if !safeIdentifier(tbl) {
			return nil, fmt.Errorf("postgres.NewStore: table %q for content type %q is not a valid SQL identifier", tbl, ct)
		}
		tables[ct] = tbl
	}
	return &Store{
		db:         cfg.DB,
		catalog:    cfg.Catalog,
		tables:     tables,
		actorHolds: fmt.Sprintf(actorHoldsTemplate, members),
	}, nil
}

var _ rbac.Authorizer = (*Store)(nil)

const roleDefinitionCols = `id, name, description, managed, content_type, created_at, modified_at`

// Can implements rbac.Authorizer: sub may perform action on obj, checked as the codename
// rbac.Codename(obj.Type, action). An action outside obj.Type's catalog is a programming
// error, surfaced as an error (→ 500) rather than a silent deny.
func (s *Store) Can(ctx context.Context, sub rbac.Subject, action rbac.Action, obj rbac.Object) (bool, error) {
	if !s.catalog.IsValid(obj.Type, action) {
		return false, wrap("postgres.Store.Can", fmt.Errorf("capability %q is not defined for content type %q", action, obj.Type))
	}
	return s.CanCodename(ctx, sub, rbac.Codename(obj.Type, action), obj)
}

// CanCodename implements rbac.Authorizer: sub holds an arbitrary codename on obj. The
// codename may name a different content type than obj (the cross-type
// create-in-container check), so it is not validated against obj.Type here.
func (s *Store) CanCodename(ctx context.Context, sub rbac.Subject, codename string, obj rbac.Object) (bool, error) {
	return s.HasCapability(ctx, sub.UserID, obj.Type, obj.ID, codename)
}

// CanGlobal implements rbac.Authorizer: sub holds codename with global scope.
func (s *Store) CanGlobal(ctx context.Context, sub rbac.Subject, codename string) (bool, error) {
	return s.HasGlobalCapability(ctx, sub.UserID, codename)
}

// VisibleIDs implements rbac.Authorizer: the object ids of t on which sub holds action,
// unifying the two tiers — a global grant of the codename sees every object of the type;
// otherwise the scoped (materialised) rows.
func (s *Store) VisibleIDs(ctx context.Context, sub rbac.Subject, action rbac.Action, t rbac.ContentType) ([]int64, error) {
	codename := rbac.Codename(t, action)
	global, err := s.HasGlobalCapability(ctx, sub.UserID, codename)
	if err != nil {
		return nil, err
	}
	if global {
		return s.AllIDsOfType(ctx, t)
	}
	return s.AccessibleIDs(ctx, sub.UserID, t, codename)
}

// AllIDsOfType returns every object id of a content type — the global-tier answer for
// holders of a global grant, who can see everything. The physical table comes from the
// injected content-type→table map.
func (s *Store) AllIDsOfType(ctx context.Context, ct rbac.ContentType) ([]int64, error) {
	table, ok := s.tables[ct]
	if !ok {
		return nil, wrap("postgres.Store.AllIDsOfType", fmt.Errorf("no table registered for content type %q", ct))
	}
	ids := []int64{}
	err := s.db.SelectContext(ctx, &ids, `SELECT id FROM `+table+` ORDER BY id`)
	return ids, wrap("postgres.Store.AllIDsOfType", err)
}

// HasCapability reports whether the user holds `codename` on (contentType, objectID),
// unifying two tiers: a GLOBAL object role whose definition grants the codename (system
// roles; no per-object rows), or a materialised evaluation row (scoped roles).
func (s *Store) HasCapability(ctx context.Context, userID int64, contentType rbac.ContentType, objectID int64, codename string) (bool, error) {
	var ok bool
	err := s.db.GetContext(ctx, &ok, `
		SELECT EXISTS (
			-- global tier: a NULL-scoped object role whose definition grants the codename
			SELECT 1
			FROM object_roles orl
			JOIN role_definition_permissions rdp ON rdp.role_definition_id = orl.role_definition_id
			JOIN dab_permissions p ON p.id = rdp.permission_id
			WHERE orl.content_type IS NULL AND p.codename = $2 AND `+s.actorHolds+`
			UNION ALL
			-- scoped tier: a materialised evaluation row for this exact object
			SELECT 1
			FROM role_evaluations e
			JOIN object_roles orl ON orl.id = e.object_role_id
			WHERE e.content_type = $3 AND e.object_id = $4 AND e.codename = $2 AND `+s.actorHolds+`
		)`, userID, codename, string(contentType), objectID)
	return ok, wrap("postgres.Store.HasCapability", err)
}

// HasGlobalCapability reports whether the user holds a global (system) role whose
// definition grants `codename` — the "see everything" tier for system roles.
func (s *Store) HasGlobalCapability(ctx context.Context, userID int64, codename string) (bool, error) {
	var ok bool
	err := s.db.GetContext(ctx, &ok, `
		SELECT EXISTS (
			SELECT 1 FROM object_roles orl
			JOIN role_definition_permissions rdp ON rdp.role_definition_id = orl.role_definition_id
			JOIN dab_permissions p ON p.id = rdp.permission_id
			WHERE orl.content_type IS NULL AND p.codename = $2 AND `+s.actorHolds+`
		)`, userID, codename)
	return ok, wrap("postgres.Store.HasGlobalCapability", err)
}

// AccessibleIDs returns the object ids of contentType on which the user holds `codename`
// via the scoped tier (materialised rows). The global tier grants every object and is
// handled by VisibleIDs, so it is not expanded here.
func (s *Store) AccessibleIDs(ctx context.Context, userID int64, contentType rbac.ContentType, codename string) ([]int64, error) {
	ids := []int64{}
	err := s.db.SelectContext(ctx, &ids, `
		SELECT DISTINCT e.object_id
		FROM role_evaluations e
		JOIN object_roles orl ON orl.id = e.object_role_id
		WHERE e.content_type = $2 AND e.codename = $3 AND `+s.actorHolds+`
		ORDER BY e.object_id`, userID, string(contentType), codename)
	return ids, wrap("postgres.Store.AccessibleIDs", err)
}

// GetRoleDefinitionByName returns a single role definition by its unique name.
func (s *Store) GetRoleDefinitionByName(ctx context.Context, name string) (rbac.RoleDefinition, error) {
	var d rbac.RoleDefinition
	err := s.db.GetContext(ctx, &d,
		`SELECT `+roleDefinitionCols+` FROM role_definitions WHERE name = $1`, name)
	return d, wrap("postgres.Store.GetRoleDefinitionByName", err)
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
func (s *Store) GiveUserPermission(ctx context.Context, defID int64, contentType *string, objectID *int64, userID int64) error {
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
	return wrap("postgres.Store.GiveUserPermission", err)
}

// GiveTeamPermission is GiveUserPermission for a team.
func (s *Store) GiveTeamPermission(ctx context.Context, defID int64, contentType *string, objectID *int64, teamID int64) error {
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
	return wrap("postgres.Store.GiveTeamPermission", err)
}

// AssignableRoles returns the RoleDefinitions that can be granted on an object of the
// given content type: the managed roles scoped to that type, plus any custom (unscoped or
// matching) definitions.
func (s *Store) AssignableRoles(ctx context.Context, contentType string) ([]rbac.RoleDefinition, error) {
	defs := []rbac.RoleDefinition{}
	err := s.db.SelectContext(ctx, &defs,
		`SELECT `+roleDefinitionCols+` FROM role_definitions
		 WHERE content_type = $1 OR (managed = false AND content_type IS NULL)
		 ORDER BY managed DESC, name`, contentType)
	return defs, wrap("postgres.Store.AssignableRoles", err)
}

// RevokeUserPermission removes a user's assignment of a definition scoped to an object.
// The object_role and its evaluation rows are left in place; access is denied on the
// next check because actorHolds joins the (now-absent) assignment live — no rebuild.
func (s *Store) RevokeUserPermission(ctx context.Context, defID int64, contentType string, objectID, userID int64) error {
	_, err := s.db.ExecContext(ctx, `
		DELETE FROM role_user_assignments ua USING object_roles orl
		WHERE ua.object_role_id = orl.id AND ua.user_id = $1
		  AND orl.role_definition_id = $2 AND orl.content_type = $3 AND orl.object_id = $4`,
		userID, defID, contentType, objectID)
	return wrap("postgres.Store.RevokeUserPermission", err)
}

// RevokeTeamPermission removes a team's assignment of a definition scoped to an object.
func (s *Store) RevokeTeamPermission(ctx context.Context, defID int64, contentType string, objectID, teamID int64) error {
	_, err := s.db.ExecContext(ctx, `
		DELETE FROM role_team_assignments ta USING object_roles orl
		WHERE ta.object_role_id = orl.id AND ta.team_id = $1
		  AND orl.role_definition_id = $2 AND orl.content_type = $3 AND orl.object_id = $4`,
		teamID, defID, contentType, objectID)
	return wrap("postgres.Store.RevokeTeamPermission", err)
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
