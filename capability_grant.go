package rbac

import (
	"context"
	"database/sql"
	"errors"

	"github.com/jmoiron/sqlx"
)

// Dual-write bridge (Gitea #97/#99): every legacy role grant is mirrored into the DAB
// capability model so capability enforcement sees runtime grants — not just the
// migrate-time backfill. These operate on sqlx.ExtContext so the same code serves both a
// *sqlx.DB (AccessChecker) and a *sqlx.Tx (the LDAP mapper's login transaction).
//
// All return (mirrored bool, err): mirrored is false when the legacy role has no
// capability equivalent (e.g. notification_admin_role) or the definition isn't seeded yet,
// so callers degrade cleanly on a pre-migration DB.

func defIDByName(ctx context.Context, ext sqlx.ExtContext, name string) (int64, bool, error) {
	var id int64
	err := sqlx.GetContext(ctx, ext, &id, `SELECT id FROM role_definitions WHERE name = $1`, name)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, false, nil
	}
	if err != nil {
		return 0, false, err
	}
	return id, true, nil
}

func ensureObjectRole(ctx context.Context, ext sqlx.ExtContext, defID int64, ct string, objID int64) (int64, error) {
	var id int64
	err := sqlx.GetContext(ctx, ext, &id,
		`SELECT id FROM object_roles WHERE role_definition_id = $1 AND content_type = $2 AND object_id = $3`,
		defID, ct, objID)
	if err == nil {
		return id, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return 0, err
	}
	err = sqlx.GetContext(ctx, ext, &id,
		`INSERT INTO object_roles (role_definition_id, content_type, object_id) VALUES ($1, $2, $3) RETURNING id`,
		defID, ct, objID)
	return id, err
}

// GrantCapabilityForLegacyFields mirrors a legacy (content_type, object_id, role_field)
// grant to a user (isUser) or team into the capability model, refreshing the cache.
func GrantCapabilityForLegacyFields(ctx context.Context, ext sqlx.ExtContext, ct string, objID int64, roleField string, actorID int64, isUser bool) (bool, error) {
	name, ok := ManagedNameForLegacy(ContentType(ct), RoleField(roleField))
	if !ok {
		return false, nil
	}
	defID, ok, err := defIDByName(ctx, ext, name)
	if err != nil || !ok {
		return false, err
	}
	orID, err := ensureObjectRole(ctx, ext, defID, ct, objID)
	if err != nil {
		return false, err
	}
	if isUser {
		_, err = ext.ExecContext(ctx,
			`INSERT INTO role_user_assignments (role_definition_id, user_id, object_role_id)
			 VALUES ($1, $2, $3) ON CONFLICT (user_id, object_role_id) DO NOTHING`, defID, actorID, orID)
	} else {
		_, err = ext.ExecContext(ctx,
			`INSERT INTO role_team_assignments (role_definition_id, team_id, object_role_id)
			 VALUES ($1, $2, $3) ON CONFLICT (team_id, object_role_id) DO NOTHING`, defID, actorID, orID)
	}
	if err != nil {
		return false, err
	}
	_, err = ext.ExecContext(ctx, `SELECT rebuild_object_role_evaluations($1)`, orID)
	return true, err
}

// RevokeCapabilityForLegacyFields removes the mirror assignment. The object_role and its
// evaluation rows are left in place (shared with other actors).
func RevokeCapabilityForLegacyFields(ctx context.Context, ext sqlx.ExtContext, ct string, objID int64, roleField string, actorID int64, isUser bool) (bool, error) {
	name, ok := ManagedNameForLegacy(ContentType(ct), RoleField(roleField))
	if !ok {
		return false, nil
	}
	defID, ok, err := defIDByName(ctx, ext, name)
	if err != nil || !ok {
		return false, err
	}
	var orID int64
	err = sqlx.GetContext(ctx, ext, &orID,
		`SELECT id FROM object_roles WHERE role_definition_id = $1 AND content_type = $2 AND object_id = $3`,
		defID, ct, objID)
	if errors.Is(err, sql.ErrNoRows) {
		return true, nil
	}
	if err != nil {
		return false, err
	}
	if isUser {
		_, err = ext.ExecContext(ctx, `DELETE FROM role_user_assignments WHERE object_role_id = $1 AND user_id = $2`, orID, actorID)
	} else {
		_, err = ext.ExecContext(ctx, `DELETE FROM role_team_assignments WHERE object_role_id = $1 AND team_id = $2`, orID, actorID)
	}
	return true, err
}
