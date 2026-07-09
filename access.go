package rbac

import (
	"context"
	"database/sql"
	"errors"

	"github.com/jmoiron/sqlx"
)

var (
	ErrAccessDenied = errors.New("access denied")
	ErrRoleNotFound = errors.New("role not found")
)

// AccessChecker provides methods to check user permissions via AWX-style RBAC
type AccessChecker struct {
	DB *sqlx.DB
}

// NewAccessChecker creates a new AccessChecker instance
func NewAccessChecker(db *sqlx.DB) *AccessChecker {
	return &AccessChecker{DB: db}
}

// UserInfo contains relevant user info for permission checking
type UserInfo struct {
	ID              int64 `db:"id"`
	IsSuperuser     bool  `db:"is_superuser"`
	IsSystemAuditor bool  `db:"is_system_auditor"`
}

// GetUserInfo retrieves user info needed for permission checks
func (a *AccessChecker) GetUserInfo(ctx context.Context, userID int64) (*UserInfo, error) {
	var info UserInfo
	err := a.DB.GetContext(ctx, &info, `
		SELECT id, is_superuser, is_system_auditor
		FROM users WHERE id = $1
	`, userID)
	if err != nil {
		return nil, err
	}
	return &info, nil
}

// UserInRole checks if a user is in a role (directly, via ancestors, or via team)
// This is the core permission check - if user is in a role, they have that role's permissions.
func (a *AccessChecker) UserInRole(ctx context.Context, userID int64, roleID int64) (bool, error) {
	// First check if user is superuser - they're in ALL roles
	var info UserInfo
	err := a.DB.GetContext(ctx, &info, `
		SELECT id, is_superuser, COALESCE(is_system_auditor, FALSE) as is_system_auditor
		FROM users WHERE id = $1
	`, userID)
	if err != nil {
		return false, err
	}
	if info.IsSuperuser {
		return true, nil
	}

	// Check via the comprehensive query
	var result bool
	err = a.DB.GetContext(ctx, &result, `
		WITH RECURSIVE
		-- Check direct membership in the role
		direct_membership AS (
			SELECT 1 FROM role_members WHERE user_id = $1 AND role_id = $2
		),
		-- Check membership in any ancestor role (user in parent role grants child role)
		ancestor_membership AS (
			SELECT 1 FROM role_members rm
			JOIN role_ancestors ra ON rm.role_id = ra.ancestor_role_id
			WHERE rm.user_id = $1 AND ra.role_id = $2
		),
		-- Check team membership where the team has this role
		team_membership AS (
			SELECT 1 FROM team_members tm
			JOIN team_roles tr ON tm.team_id = tr.team_id
			WHERE tm.user_id = $1 AND tr.role_id = $2
		),
		-- Check team membership where team has ancestor role
		team_ancestor_membership AS (
			SELECT 1 FROM team_members tm
			JOIN team_roles tr ON tm.team_id = tr.team_id
			JOIN role_ancestors ra ON tr.role_id = ra.ancestor_role_id
			WHERE tm.user_id = $1 AND ra.role_id = $2
		)
		SELECT 
			EXISTS (SELECT 1 FROM direct_membership)
			OR EXISTS (SELECT 1 FROM ancestor_membership)
			OR EXISTS (SELECT 1 FROM team_membership)
			OR EXISTS (SELECT 1 FROM team_ancestor_membership)
	`, userID, roleID)

	return result, err
}

// GetObjectRole retrieves the role for a specific field on an object
func (a *AccessChecker) GetObjectRole(ctx context.Context, contentType ContentType, objectID int64, roleField RoleField) (*Role, error) {
	var role Role
	err := a.DB.GetContext(ctx, &role, `
		SELECT id, role_field, singleton_name, content_type, object_id, name, description, created_at, modified_at
		FROM roles
		WHERE content_type = $1 AND object_id = $2 AND role_field = $3
	`, string(contentType), objectID, string(roleField))
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrRoleNotFound
		}
		return nil, err
	}
	return &role, nil
}

// GetSingletonRole retrieves a system singleton role
func (a *AccessChecker) GetSingletonRole(ctx context.Context, singletonName SingletonRole) (*Role, error) {
	var role Role
	err := a.DB.GetContext(ctx, &role, `
		SELECT id, role_field, singleton_name, content_type, object_id, name, description, created_at, modified_at
		FROM roles
		WHERE singleton_name = $1
	`, string(singletonName))
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrRoleNotFound
		}
		return nil, err
	}
	return &role, nil
}

// CanRead checks if user has read access to an object
func (a *AccessChecker) CanRead(ctx context.Context, userID int64, contentType ContentType, objectID int64) (bool, error) {
	// Check superuser first
	info, err := a.GetUserInfo(ctx, userID)
	if err != nil {
		return false, err
	}
	if info.IsSuperuser || info.IsSystemAuditor {
		return true, nil
	}

	// Get the read_role for this object
	role, err := a.GetObjectRole(ctx, contentType, objectID, RoleFieldRead)
	if err != nil {
		if errors.Is(err, ErrRoleNotFound) {
			return false, nil
		}
		return false, err
	}

	return a.UserInRole(ctx, userID, role.ID)
}

// HasObjectRole reports whether the user holds roleField on (contentType,
// objectID), directly or through the role hierarchy. Superusers always pass.
//
// Because parents inherit their children via role_ancestors, checking a
// fine-grained role also admits everyone above it: the object admin, the org's
// delegated sub-admin, the org admin, and the system administrator. That is why
// callers only ever check the *most specific* role an action needs — there is
// no need for "admin OR sub-admin" style disjunctions.
func (a *AccessChecker) HasObjectRole(ctx context.Context, userID int64, contentType ContentType, objectID int64, roleField RoleField) (bool, error) {
	info, err := a.GetUserInfo(ctx, userID)
	if err != nil {
		return false, err
	}
	if info.IsSuperuser {
		return true, nil
	}

	role, err := a.GetObjectRole(ctx, contentType, objectID, roleField)
	if err != nil {
		if errors.Is(err, ErrRoleNotFound) {
			return false, nil
		}
		return false, err
	}

	return a.UserInRole(ctx, userID, role.ID)
}

// CanAdmin checks if user has admin access to an object.
func (a *AccessChecker) CanAdmin(ctx context.Context, userID int64, contentType ContentType, objectID int64) (bool, error) {
	return a.HasObjectRole(ctx, userID, contentType, objectID, RoleFieldAdmin)
}

// CanExecute checks if user has execute access to an object (job template, organization).
func (a *AccessChecker) CanExecute(ctx context.Context, userID int64, contentType ContentType, objectID int64) (bool, error) {
	return a.HasObjectRole(ctx, userID, contentType, objectID, RoleFieldExecute)
}

// CanUse checks if user can use a resource (project, inventory, credential).
func (a *AccessChecker) CanUse(ctx context.Context, userID int64, contentType ContentType, objectID int64) (bool, error) {
	return a.HasObjectRole(ctx, userID, contentType, objectID, RoleFieldUse)
}

// contentTables is the single source of truth mapping an RBAC content type to
// its backing table. Adding a new RBAC-scoped resource is one entry here (plus its
// per-object role trigger — copy db/migrations/TEMPLATE_rbac_resource.sql). Table
// names are compile-time constants (never user input), so interpolating them into
// queries below is safe. It replaced three parallel switch statements (B8/#87).
var contentTables = map[ContentType]string{
	ContentTypeOrganization:     "organizations",
	ContentTypeTeam:             "teams",
	ContentTypeProject:          "projects",
	ContentTypeInventory:        "inventories",
	ContentTypeJobTemplate:      "job_templates",
	ContentTypeWorkflowTemplate: "workflow_templates",
	ContentTypeCredential:       "credentials",
}

// allIDsOfType returns every object id of a content type — used for the superuser
// and system-auditor "see everything" paths.
func (a *AccessChecker) allIDsOfType(ctx context.Context, contentType ContentType) ([]int64, error) {
	table, ok := contentTables[contentType]
	if !ok {
		return nil, nil
	}
	var ids []int64
	err := a.DB.SelectContext(ctx, &ids, "SELECT id FROM "+table)
	return ids, err
}

// OrgForContent returns the owning organization id of an org-scoped object and
// whether it could be determined. For ContentTypeOrganization the object is the
// org itself; resource types resolve via their organization_id column (table from
// contentTables, never user input, so the interpolation is safe).
func (a *AccessChecker) OrgForContent(ctx context.Context, contentType ContentType, objectID int64) (int64, bool) {
	if contentType == ContentTypeOrganization {
		return objectID, true
	}
	table, ok := contentTables[contentType]
	if !ok {
		return 0, false
	}
	var org int64
	if err := a.DB.GetContext(ctx, &org, "SELECT organization_id FROM "+table+" WHERE id = $1", objectID); err != nil {
		return 0, false
	}
	return org, true
}

// UserIsOrgMember reports whether the user belongs to the organization (holds its
// member_role directly or via the role hierarchy). Superusers always pass.
func (a *AccessChecker) UserIsOrgMember(ctx context.Context, userID, orgID int64) (bool, error) {
	role, err := a.GetObjectRole(ctx, ContentTypeOrganization, orgID, RoleFieldMember)
	if err != nil {
		if errors.Is(err, ErrRoleNotFound) {
			return false, nil
		}
		return false, err
	}
	return a.UserInRole(ctx, userID, role.ID)
}

// FilterAccessibleIDs returns only the IDs the user can access with the given role
func (a *AccessChecker) FilterAccessibleIDs(ctx context.Context, userID int64, contentType ContentType, roleField RoleField) ([]int64, error) {
	info, err := a.GetUserInfo(ctx, userID)
	if err != nil {
		return nil, err
	}

	// Superuser can access everything.
	if info.IsSuperuser {
		return a.allIDsOfType(ctx, contentType)
	}

	// System auditor can read everything.
	if info.IsSystemAuditor && roleField == RoleFieldRead {
		return a.allIDsOfType(ctx, contentType)
	}

	// For regular users, find objects where they have the role
	var ids []int64
	err = a.DB.SelectContext(ctx, &ids, `
		WITH user_accessible_roles AS (
			-- Roles user is directly a member of
			SELECT role_id FROM role_members WHERE user_id = $1
			UNION
			-- Roles that have ancestors the user is a member of
			SELECT ra.role_id 
			FROM role_ancestors ra
			JOIN role_members rm ON ra.ancestor_role_id = rm.role_id
			WHERE rm.user_id = $1
			UNION
			-- Roles assigned to teams the user is a member of
			SELECT tr.role_id
			FROM team_roles tr
			JOIN team_members tm ON tr.team_id = tm.team_id
			WHERE tm.user_id = $1
			UNION
			-- Roles that have ancestors assigned to user's teams
			SELECT ra.role_id
			FROM role_ancestors ra
			JOIN team_roles tr ON ra.ancestor_role_id = tr.role_id
			JOIN team_members tm ON tr.team_id = tm.team_id
			WHERE tm.user_id = $1
		)
		SELECT DISTINCT r.object_id
		FROM roles r
		JOIN user_accessible_roles uar ON r.id = uar.role_id
		WHERE r.content_type = $2 AND r.role_field = $3 AND r.object_id IS NOT NULL
	`, userID, string(contentType), string(roleField))

	return ids, err
}

// GetObjectRoles returns all roles for a given object
func (a *AccessChecker) GetObjectRoles(ctx context.Context, contentType ContentType, objectID int64) ([]Role, error) {
	var roles []Role
	err := a.DB.SelectContext(ctx, &roles, `
		SELECT id, role_field, singleton_name, content_type, object_id, name, description, created_at, modified_at
		FROM roles
		WHERE content_type = $1 AND object_id = $2
		ORDER BY role_field
	`, string(contentType), objectID)
	return roles, err
}

// GetRoleMembers returns all users directly in a role
func (a *AccessChecker) GetRoleMembers(ctx context.Context, roleID int64) ([]RoleMember, error) {
	var members []RoleMember
	err := a.DB.SelectContext(ctx, &members, `
		SELECT id, role_id, user_id, created_at
		FROM role_members
		WHERE role_id = $1
	`, roleID)
	return members, err
}

// GetRoleTeams returns all teams assigned to a role
func (a *AccessChecker) GetRoleTeams(ctx context.Context, roleID int64) ([]TeamRole, error) {
	var teams []TeamRole
	err := a.DB.SelectContext(ctx, &teams, `
		SELECT id, team_id, role_id, created_at
		FROM team_roles
		WHERE role_id = $1
	`, roleID)
	return teams, err
}

// AddUserToRole adds a user to a role
func (a *AccessChecker) AddUserToRole(ctx context.Context, roleID int64, userID int64) error {
	_, err := a.DB.ExecContext(ctx, `
		INSERT INTO role_members (role_id, user_id)
		VALUES ($1, $2)
		ON CONFLICT (role_id, user_id) DO NOTHING
	`, roleID, userID)
	return err
}

// RemoveUserFromRole removes a user from a role
func (a *AccessChecker) RemoveUserFromRole(ctx context.Context, roleID int64, userID int64) error {
	_, err := a.DB.ExecContext(ctx, `
		DELETE FROM role_members
		WHERE role_id = $1 AND user_id = $2
	`, roleID, userID)
	return err
}

// AddTeamToRole adds a team to a role
func (a *AccessChecker) AddTeamToRole(ctx context.Context, roleID int64, teamID int64) error {
	_, err := a.DB.ExecContext(ctx, `
		INSERT INTO team_roles (role_id, team_id)
		VALUES ($1, $2)
		ON CONFLICT (role_id, team_id) DO NOTHING
	`, roleID, teamID)
	return err
}

// RemoveTeamFromRole removes a team from a role
func (a *AccessChecker) RemoveTeamFromRole(ctx context.Context, roleID int64, teamID int64) error {
	_, err := a.DB.ExecContext(ctx, `
		DELETE FROM team_roles
		WHERE role_id = $1 AND team_id = $2
	`, roleID, teamID)
	return err
}

// GetUserRoles returns all roles a user has (directly or through teams)
func (a *AccessChecker) GetUserRoles(ctx context.Context, userID int64) ([]Role, error) {
	var roles []Role
	err := a.DB.SelectContext(ctx, &roles, `
		WITH user_role_ids AS (
			-- Direct membership
			SELECT role_id FROM role_members WHERE user_id = $1
			UNION
			-- Via team membership
			SELECT tr.role_id
			FROM team_roles tr
			JOIN team_members tm ON tr.team_id = tm.team_id
			WHERE tm.user_id = $1
		)
		SELECT DISTINCT r.id, r.role_field, r.singleton_name, r.content_type, r.object_id, r.name, r.description, r.created_at, r.modified_at
		FROM roles r
		JOIN user_role_ids uri ON r.id = uri.role_id
		ORDER BY r.content_type, r.object_id, r.role_field
	`, userID)
	return roles, err
}
