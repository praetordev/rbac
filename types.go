// Package rbac provides a capability-based Role-Based Access Control engine:
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

// SingletonRole represents system-wide roles.
type SingletonRole string

const (
	SingletonSystemAdministrator SingletonRole = "system_administrator"
	SingletonSystemAuditor       SingletonRole = "system_auditor"
)
