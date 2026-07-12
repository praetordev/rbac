// Package rbac provides Praetor's capability-based Role-Based Access Control:
// the capability catalog, managed role definitions, and the Authorizer contract
// (policy-decision-point interface) the services enforce against.
package rbac

// ContentType represents the type of object a capability applies to (polymorphic).
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

// RoleField is the legacy per-object role-slot name. It survives as the
// compatibility vocabulary the api still speaks for org membership, create-in-org
// gating, and creator-grants — each resolved to a managed RoleDefinition via
// ManagedNameForLegacy. The AWX role-hierarchy tables it originally keyed were
// dropped in migration 000057; retiring RoleField itself is the remaining step of
// the capability migration.
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

// SingletonRole represents system-wide roles.
type SingletonRole string

const (
	SingletonSystemAdministrator SingletonRole = "system_administrator"
	SingletonSystemAuditor       SingletonRole = "system_auditor"
)
