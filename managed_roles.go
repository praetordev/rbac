package rbac

// ── Built-in (managed) role definitions ─────────────────────────────────────────
//
// The built-in RoleDefinitions whose capability (codename) sets define the standard
// roles. cmd/migrator seeds role_definitions + role_definition_permissions from
// ManagedRoles() idempotently (managed=true, id-stable), and they are the concrete
// definitions custom-role and by-name grant paths target.
//
// Modelling notes:
//   - A managed role's ContentType is the object type it is ASSIGNED to. Org-level
//     roles (org admin, the *_admin delegates, auditor, execute, approval) are assigned
//     to the organization, yet their codenames span CHILD types (e.g. org auditor holds
//     view_inventory). Evaluation propagates a child-typed permission held at org scope
//     down to the org's children — so we list child codenames here, we do not bake
//     per-object rows.
//   - `add_*` is an org-scoped capability (create children), so it appears only on
//     org-level definitions, never on object-level admin.
//   - Approval is a distinct authority: workflow admin does NOT include approve.
//
// The declaration is the single source of truth.

// ManagedRole is a built-in RoleDefinition.
type ManagedRole struct {
	Name        string
	Description string
	// ContentType is the object type this role is assigned to; "" means a global
	// singleton (system role) with no object scope.
	ContentType ContentType
	// Singleton is set for the two system roles; "" otherwise.
	Singleton SingletonRole
	// Codenames is the exact capability set this role confers.
	Codenames []string
}

// caps builds codenames for a content type from an explicit action list.
func caps(ct ContentType, actions ...Action) []string {
	out := make([]string, 0, len(actions))
	for _, a := range actions {
		out = append(out, Codename(ct, a))
	}
	return out
}

// allCaps returns every codename declared for a content type, in catalog order.
func allCaps(ct ContentType) []string {
	acts := capabilityCatalog[ct]
	out := make([]string, 0, len(acts))
	for _, a := range acts {
		out = append(out, Codename(ct, a))
	}
	return out
}

// viewOf returns the view_* codename for each content type given.
func viewOf(cts ...ContentType) []string {
	out := make([]string, 0, len(cts))
	for _, ct := range cts {
		out = append(out, Codename(ct, ActionView))
	}
	return out
}

func concat(lists ...[]string) []string {
	var out []string
	for _, l := range lists {
		out = append(out, l...)
	}
	return out
}

// orgChildTypes are the object types that live inside an organization; org-level roles
// project their capabilities across these.
var orgChildTypes = []ContentType{
	ContentTypeTeam, ContentTypeProject, ContentTypeInventory,
	ContentTypeCredential, ContentTypeJobTemplate, ContentTypeWorkflowTemplate,
}

// everyCodename returns the full catalog (used by System Administrator / Org Admin).
func everyCodename() []string {
	var out []string
	for _, ct := range capabilityContentTypeOrder {
		out = append(out, allCaps(ct)...)
	}
	return out
}

// everyViewCodename returns view_* for every content type (System / Org Auditor).
func everyViewCodename() []string {
	return viewOf(capabilityContentTypeOrder...)
}

// ManagedRoles returns the full managed-mirror declaration in a stable order.
func ManagedRoles() []ManagedRole {
	org := ContentTypeOrganization
	return []ManagedRole{
		// ── System singletons ──────────────────────────────────────────────
		{
			Name: "System Administrator", Description: "Full access to everything.",
			Singleton: SingletonSystemAdministrator,
			Codenames: concat(everyCodename(), systemAdminCodenames()),
		},
		{
			Name: "System Auditor", Description: "Read-only access to everything.",
			Singleton: SingletonSystemAuditor,
			Codenames: concat(everyViewCodename(), systemAuditorCodenames()),
		},

		// ── Organization roles (assigned to the org; codenames span children) ─
		{
			Name: "Organization Admin", Description: "Manage all aspects of the organization.",
			ContentType: org, Codenames: everyCodename(),
		},
		{
			Name: "Organization Member", Description: "Belong to the organization.",
			ContentType: org, Codenames: viewOf(org),
		},
		{
			Name: "Organization Read", Description: "View the organization's settings.",
			ContentType: org, Codenames: viewOf(org),
		},
		{
			Name: "Organization Auditor", Description: "View all aspects of the organization.",
			ContentType: org,
			Codenames:   concat(viewOf(org), viewOf(orgChildTypes...)),
		},
		{
			Name: "Organization Execute", Description: "Run any executable resource in the organization.",
			ContentType: org,
			// Org execute runs both job templates and workflows (000048 + 000049).
			Codenames: concat(
				caps(ContentTypeJobTemplate, ActionExecute, ActionView),
				caps(ContentTypeWorkflowTemplate, ActionExecute, ActionView),
			),
		},
		{
			Name: "Organization Project Admin", Description: "Manage all projects in the organization.",
			ContentType: org, Codenames: allCaps(ContentTypeProject),
		},
		{
			Name: "Organization Inventory Admin", Description: "Manage all inventories in the organization.",
			ContentType: org, Codenames: allCaps(ContentTypeInventory),
		},
		{
			Name: "Organization Credential Admin", Description: "Manage all credentials in the organization.",
			ContentType: org, Codenames: allCaps(ContentTypeCredential),
		},
		{
			Name: "Organization Job Template Admin", Description: "Manage all job templates in the organization.",
			ContentType: org, Codenames: allCaps(ContentTypeJobTemplate),
		},
		{
			Name: "Organization Workflow Admin", Description: "Manage all workflow templates in the organization.",
			ContentType: org,
			// No approve: managing a workflow != approving its gates (000049).
			Codenames: caps(ContentTypeWorkflowTemplate, ActionAdd, ActionView, ActionChange, ActionDelete, ActionManage, ActionExecute),
		},
		{
			Name: "Organization Approval", Description: "Approve or deny workflow approval nodes in the organization.",
			ContentType: org,
			Codenames:   caps(ContentTypeWorkflowTemplate, ActionApprove, ActionView),
		},

		// ── Project roles ──────────────────────────────────────────────────
		{
			Name: "Project Admin", Description: "Manage all aspects of the project.",
			ContentType: ContentTypeProject,
			Codenames:   caps(ContentTypeProject, ActionView, ActionChange, ActionDelete, ActionManage, ActionUse, ActionUpdate),
		},
		{
			Name: "Project Use", Description: "Use the project in a job template.",
			ContentType: ContentTypeProject,
			Codenames:   caps(ContentTypeProject, ActionUse, ActionView),
		},
		{
			Name: "Project Update", Description: "Update the project from SCM.",
			ContentType: ContentTypeProject,
			Codenames:   caps(ContentTypeProject, ActionUpdate, ActionView),
		},
		{
			Name: "Project Read", Description: "View the project.",
			ContentType: ContentTypeProject,
			Codenames:   caps(ContentTypeProject, ActionView),
		},

		// ── Inventory roles ────────────────────────────────────────────────
		{
			Name: "Inventory Admin", Description: "Manage all aspects of the inventory.",
			ContentType: ContentTypeInventory,
			Codenames:   caps(ContentTypeInventory, ActionView, ActionChange, ActionDelete, ActionManage, ActionUse, ActionUpdate, ActionAdhoc),
		},
		{
			Name: "Inventory Use", Description: "Use the inventory in a job template.",
			ContentType: ContentTypeInventory,
			Codenames:   caps(ContentTypeInventory, ActionUse, ActionView),
		},
		{
			Name: "Inventory Update", Description: "Update the inventory's sources.",
			ContentType: ContentTypeInventory,
			Codenames:   caps(ContentTypeInventory, ActionUpdate, ActionView),
		},
		{
			Name: "Inventory Adhoc", Description: "Run ad-hoc commands on the inventory.",
			ContentType: ContentTypeInventory,
			Codenames:   caps(ContentTypeInventory, ActionAdhoc, ActionView),
		},
		{
			Name: "Inventory Read", Description: "View the inventory.",
			ContentType: ContentTypeInventory,
			Codenames:   caps(ContentTypeInventory, ActionView),
		},

		// ── Credential roles ───────────────────────────────────────────────
		{
			Name: "Credential Admin", Description: "Manage all aspects of the credential.",
			ContentType: ContentTypeCredential,
			Codenames:   caps(ContentTypeCredential, ActionView, ActionChange, ActionDelete, ActionManage, ActionUse),
		},
		{
			Name: "Credential Use", Description: "Use the credential in a job template.",
			ContentType: ContentTypeCredential,
			Codenames:   caps(ContentTypeCredential, ActionUse, ActionView),
		},
		{
			Name: "Credential Read", Description: "View the credential.",
			ContentType: ContentTypeCredential,
			Codenames:   caps(ContentTypeCredential, ActionView),
		},

		// ── Job template roles ─────────────────────────────────────────────
		{
			Name: "Job Template Admin", Description: "Manage all aspects of the job template.",
			ContentType: ContentTypeJobTemplate,
			Codenames:   caps(ContentTypeJobTemplate, ActionView, ActionChange, ActionDelete, ActionManage, ActionExecute),
		},
		{
			Name: "Job Template Execute", Description: "Execute the job template.",
			ContentType: ContentTypeJobTemplate,
			Codenames:   caps(ContentTypeJobTemplate, ActionExecute, ActionView),
		},
		{
			Name: "Job Template Read", Description: "View the job template.",
			ContentType: ContentTypeJobTemplate,
			Codenames:   caps(ContentTypeJobTemplate, ActionView),
		},

		// ── Workflow template roles ────────────────────────────────────────
		{
			Name: "Workflow Template Admin", Description: "Manage all aspects of the workflow template.",
			ContentType: ContentTypeWorkflowTemplate,
			Codenames:   caps(ContentTypeWorkflowTemplate, ActionView, ActionChange, ActionDelete, ActionManage, ActionExecute),
		},
		{
			Name: "Workflow Template Execute", Description: "Launch the workflow template.",
			ContentType: ContentTypeWorkflowTemplate,
			Codenames:   caps(ContentTypeWorkflowTemplate, ActionExecute, ActionView),
		},
		{
			Name: "Workflow Template Approve", Description: "Approve or deny the workflow's approval nodes.",
			ContentType: ContentTypeWorkflowTemplate,
			Codenames:   caps(ContentTypeWorkflowTemplate, ActionApprove, ActionView),
		},
		{
			Name: "Workflow Template Read", Description: "View the workflow template.",
			ContentType: ContentTypeWorkflowTemplate,
			Codenames:   caps(ContentTypeWorkflowTemplate, ActionView),
		},

		// ── Team roles ─────────────────────────────────────────────────────
		{
			Name: "Team Admin", Description: "Manage all aspects of the team.",
			ContentType: ContentTypeTeam,
			Codenames:   caps(ContentTypeTeam, ActionView, ActionChange, ActionDelete, ActionManage),
		},
		{
			Name: "Team Member", Description: "Belong to the team.",
			ContentType: ContentTypeTeam,
			Codenames:   caps(ContentTypeTeam, ActionView),
		},
		{
			Name: "Team Read", Description: "View the team.",
			ContentType: ContentTypeTeam,
			Codenames:   caps(ContentTypeTeam, ActionView),
		},
	}
}
