// Package rbac provides AWX-style Role-Based Access Control for Praetor.
// It implements role hierarchy, implicit roles, and permission checking.
package rbac

import (
	"time"
)

// ContentType represents the type of object a role belongs to (polymorphic)
type ContentType string

const (
	ContentTypeOrganization ContentType = "organization"
	ContentTypeTeam         ContentType = "team"
	ContentTypeProject      ContentType = "project"
	ContentTypeInventory    ContentType = "inventory"
	ContentTypeJobTemplate  ContentType = "job_template"
	ContentTypeCredential   ContentType = "credential"
	// Workflow templates are first-class RBAC objects (Gitea #60): per-workflow
	// admin/execute/approval/read roles, parented to the org's workflow_admin/
	// execute/approval/auditor roles (see migration 000049).
	ContentTypeWorkflowTemplate ContentType = "workflow_template"
)

// RoleField represents the type of role on an object
type RoleField string

const (
	// Organization roles
	RoleFieldAdmin             RoleField = "admin_role"
	RoleFieldMember            RoleField = "member_role"
	RoleFieldRead              RoleField = "read_role"
	RoleFieldAuditor           RoleField = "auditor_role"
	RoleFieldExecute           RoleField = "execute_role"
	RoleFieldProjectAdmin      RoleField = "project_admin_role"
	RoleFieldInventoryAdmin    RoleField = "inventory_admin_role"
	RoleFieldCredentialAdmin   RoleField = "credential_admin_role"
	RoleFieldWorkflowAdmin     RoleField = "workflow_admin_role"
	RoleFieldNotificationAdmin RoleField = "notification_admin_role"
	RoleFieldJobTemplateAdmin  RoleField = "job_template_admin_role"
	RoleFieldApproval          RoleField = "approval_role"

	// Resource roles
	RoleFieldUse    RoleField = "use_role"
	RoleFieldUpdate RoleField = "update_role"
	// RoleFieldAdhoc is a reserved slot (see Gitea #60): the inventory adhoc_role
	// is created by the trigger with the correct hierarchy (child of inventory
	// admin, parent of read) but is not checked anywhere because there is no
	// ad-hoc-command feature yet to gate. Wire it up when that feature lands.
	RoleFieldAdhoc RoleField = "adhoc_role"
)

// SingletonRole represents system-wide roles
type SingletonRole string

const (
	SingletonSystemAdministrator SingletonRole = "system_administrator"
	SingletonSystemAuditor       SingletonRole = "system_auditor"
)

// Role represents an AWX-style role with hierarchy support
type Role struct {
	ID            int64     `db:"id" json:"id"`
	RoleField     string    `db:"role_field" json:"role_field"`
	SingletonName *string   `db:"singleton_name" json:"singleton_name,omitempty"`
	ContentType   *string   `db:"content_type" json:"content_type,omitempty"`
	ObjectID      *int64    `db:"object_id" json:"object_id,omitempty"`
	Name          *string   `db:"name" json:"name,omitempty"`
	Description   *string   `db:"description" json:"description,omitempty"`
	CreatedAt     time.Time `db:"created_at" json:"created_at"`
	ModifiedAt    time.Time `db:"modified_at" json:"modified_at"`
}

// RoleParent represents a parent-child relationship between roles
type RoleParent struct {
	ID           int64     `db:"id" json:"id"`
	RoleID       int64     `db:"role_id" json:"role_id"`
	ParentRoleID int64     `db:"parent_role_id" json:"parent_role_id"`
	CreatedAt    time.Time `db:"created_at" json:"created_at"`
}

// RoleAncestor represents a computed ancestor relationship for efficient lookups
type RoleAncestor struct {
	ID             int64 `db:"id" json:"id"`
	RoleID         int64 `db:"role_id" json:"role_id"`
	AncestorRoleID int64 `db:"ancestor_role_id" json:"ancestor_role_id"`
}

// RoleMember represents a user's direct membership in a role
type RoleMember struct {
	ID        int64     `db:"id" json:"id"`
	RoleID    int64     `db:"role_id" json:"role_id"`
	UserID    int64     `db:"user_id" json:"user_id"`
	CreatedAt time.Time `db:"created_at" json:"created_at"`
}

// TeamRole represents a team's assignment to a role
type TeamRole struct {
	ID        int64     `db:"id" json:"id"`
	TeamID    int64     `db:"team_id" json:"team_id"`
	RoleID    int64     `db:"role_id" json:"role_id"`
	CreatedAt time.Time `db:"created_at" json:"created_at"`
}

// RoleWithSummary extends Role with computed fields for API responses
type RoleWithSummary struct {
	Role
	UserCount int64          `json:"user_count,omitempty"`
	TeamCount int64          `json:"team_count,omitempty"`
	Summary   map[string]any `json:"summary_fields,omitempty"`
}

// Permission actions
const (
	PermissionRead    = "read"
	PermissionCreate  = "create"
	PermissionUpdate  = "update"
	PermissionDelete  = "delete"
	PermissionExecute = "execute"
	PermissionAdmin   = "admin"
	PermissionUse     = "use"
	PermissionAdhoc   = "adhoc"
)
