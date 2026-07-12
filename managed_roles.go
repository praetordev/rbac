package rbac

// ── Managed-mirror of the legacy roles (Gitea #95, epic #93) ────────────────────
//
// For every fixed role_field the legacy RBAC enforces, we declare a managed=true
// RoleDefinition whose capability (codename) set reproduces what that role grants
// today. This is the compatibility layer of the DAB port: the managed set exists so
// current behaviour is preserved before any custom role is created, and so LDAP-by-name
// (#98) and the enforcement swap (#97) have concrete definitions to target.
//
// Modelling notes, matching AWX/DAB:
//   - A managed role's ContentType is the object type it is ASSIGNED to. Org-level
//     roles (org admin, the *_admin delegates, auditor, execute, approval) are assigned
//     to the organization, yet their codenames span CHILD types (e.g. org auditor holds
//     view_inventory). #96's evaluation propagates a child-typed permission held at org
//     scope down to the org's children — so we list child codenames here, we do not bake
//     per-object rows.
//   - `add_*` is an org-scoped capability (create children), so it appears only on
//     org-level definitions, never on object-level admin.
//   - Approval is a distinct authority: workflow admin does NOT include approve
//     (mirrors 000049, where wf admin_role is not a parent of approval_role).
//   - notification_admin_role has no catalog codenames yet (notifications aren't a
//     capability content type); it is intentionally omitted until they are.
//
// The declaration is the single source of truth; cmd/migrator seeds role_definitions +
// role_definition_permissions from ManagedRoles() idempotently (managed=true, id-stable).

// ManagedRole is a built-in RoleDefinition mirroring one legacy role.
type ManagedRole struct {
	Name        string
	Description string
	// ContentType is the object type this role is assigned to; "" means a global
	// singleton (system role) with no object scope.
	ContentType ContentType
	// RoleField is the legacy role_field this mirrors ("" for singletons). Together
	// with ContentType it is the ROLE_DEFINITION_TO_ROLE_FIELD mapping DAB keeps for
	// dual-run sync.
	RoleField RoleField
	// Singleton is set for the two system roles; "" otherwise.
	Singleton SingletonRole
	// Codenames is the exact capability set this role confers.
	Codenames []string
}

// ManagedNameForLegacy returns the managed RoleDefinition name that mirrors a legacy
// object/org role_field, for backfilling legacy grants into the capability model.
func ManagedNameForLegacy(ct ContentType, rf RoleField) (string, bool) {
	for _, mr := range ManagedRoles() {
		if mr.Singleton == "" && mr.ContentType == ct && mr.RoleField == rf {
			return mr.Name, true
		}
	}
	return "", false
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
			Singleton: SingletonSystemAdministrator, Codenames: everyCodename(),
		},
		{
			Name: "System Auditor", Description: "Read-only access to everything.",
			Singleton: SingletonSystemAuditor, Codenames: everyViewCodename(),
		},

		// ── Organization roles (assigned to the org; codenames span children) ─
		{
			Name: "Organization Admin", Description: "Manage all aspects of the organization.",
			ContentType: org, RoleField: RoleFieldAdmin, Codenames: everyCodename(),
		},
		{
			Name: "Organization Member", Description: "Belong to the organization.",
			ContentType: org, RoleField: RoleFieldMember, Codenames: viewOf(org),
		},
		{
			Name: "Organization Read", Description: "View the organization's settings.",
			ContentType: org, RoleField: RoleFieldRead, Codenames: viewOf(org),
		},
		{
			Name: "Organization Auditor", Description: "View all aspects of the organization.",
			ContentType: org, RoleField: RoleFieldAuditor,
			Codenames: concat(viewOf(org), viewOf(orgChildTypes...)),
		},
		{
			Name: "Organization Execute", Description: "Run any executable resource in the organization.",
			ContentType: org, RoleField: RoleFieldExecute,
			// Org execute runs both job templates and workflows (000048 + 000049).
			Codenames: concat(
				caps(ContentTypeJobTemplate, ActionExecute, ActionView),
				caps(ContentTypeWorkflowTemplate, ActionExecute, ActionView),
			),
		},
		{
			Name: "Organization Project Admin", Description: "Manage all projects in the organization.",
			ContentType: org, RoleField: RoleFieldProjectAdmin, Codenames: allCaps(ContentTypeProject),
		},
		{
			Name: "Organization Inventory Admin", Description: "Manage all inventories in the organization.",
			ContentType: org, RoleField: RoleFieldInventoryAdmin, Codenames: allCaps(ContentTypeInventory),
		},
		{
			Name: "Organization Credential Admin", Description: "Manage all credentials in the organization.",
			ContentType: org, RoleField: RoleFieldCredentialAdmin, Codenames: allCaps(ContentTypeCredential),
		},
		{
			Name: "Organization Job Template Admin", Description: "Manage all job templates in the organization.",
			ContentType: org, RoleField: RoleFieldJobTemplateAdmin, Codenames: allCaps(ContentTypeJobTemplate),
		},
		{
			Name: "Organization Workflow Admin", Description: "Manage all workflow templates in the organization.",
			ContentType: org, RoleField: RoleFieldWorkflowAdmin,
			// No approve: managing a workflow != approving its gates (000049).
			Codenames: caps(ContentTypeWorkflowTemplate, ActionAdd, ActionView, ActionChange, ActionDelete, ActionManage, ActionExecute),
		},
		{
			Name: "Organization Approval", Description: "Approve or deny workflow approval nodes in the organization.",
			ContentType: org, RoleField: RoleFieldApproval,
			Codenames: caps(ContentTypeWorkflowTemplate, ActionApprove, ActionView),
		},

		// ── Project roles ──────────────────────────────────────────────────
		{
			Name: "Project Admin", Description: "Manage all aspects of the project.",
			ContentType: ContentTypeProject, RoleField: RoleFieldAdmin,
			Codenames: caps(ContentTypeProject, ActionView, ActionChange, ActionDelete, ActionManage, ActionUse, ActionUpdate),
		},
		{
			Name: "Project Use", Description: "Use the project in a job template.",
			ContentType: ContentTypeProject, RoleField: RoleFieldUse,
			Codenames: caps(ContentTypeProject, ActionUse, ActionView),
		},
		{
			Name: "Project Update", Description: "Update the project from SCM.",
			ContentType: ContentTypeProject, RoleField: RoleFieldUpdate,
			Codenames: caps(ContentTypeProject, ActionUpdate, ActionView),
		},
		{
			Name: "Project Read", Description: "View the project.",
			ContentType: ContentTypeProject, RoleField: RoleFieldRead,
			Codenames: caps(ContentTypeProject, ActionView),
		},

		// ── Inventory roles ────────────────────────────────────────────────
		{
			Name: "Inventory Admin", Description: "Manage all aspects of the inventory.",
			ContentType: ContentTypeInventory, RoleField: RoleFieldAdmin,
			Codenames: caps(ContentTypeInventory, ActionView, ActionChange, ActionDelete, ActionManage, ActionUse, ActionUpdate, ActionAdhoc),
		},
		{
			Name: "Inventory Use", Description: "Use the inventory in a job template.",
			ContentType: ContentTypeInventory, RoleField: RoleFieldUse,
			Codenames: caps(ContentTypeInventory, ActionUse, ActionView),
		},
		{
			Name: "Inventory Update", Description: "Update the inventory's sources.",
			ContentType: ContentTypeInventory, RoleField: RoleFieldUpdate,
			Codenames: caps(ContentTypeInventory, ActionUpdate, ActionView),
		},
		{
			Name: "Inventory Adhoc", Description: "Run ad-hoc commands on the inventory.",
			ContentType: ContentTypeInventory, RoleField: RoleFieldAdhoc,
			Codenames: caps(ContentTypeInventory, ActionAdhoc, ActionView),
		},
		{
			Name: "Inventory Read", Description: "View the inventory.",
			ContentType: ContentTypeInventory, RoleField: RoleFieldRead,
			Codenames: caps(ContentTypeInventory, ActionView),
		},

		// ── Credential roles ───────────────────────────────────────────────
		{
			Name: "Credential Admin", Description: "Manage all aspects of the credential.",
			ContentType: ContentTypeCredential, RoleField: RoleFieldAdmin,
			Codenames: caps(ContentTypeCredential, ActionView, ActionChange, ActionDelete, ActionManage, ActionUse),
		},
		{
			Name: "Credential Use", Description: "Use the credential in a job template.",
			ContentType: ContentTypeCredential, RoleField: RoleFieldUse,
			Codenames: caps(ContentTypeCredential, ActionUse, ActionView),
		},
		{
			Name: "Credential Read", Description: "View the credential.",
			ContentType: ContentTypeCredential, RoleField: RoleFieldRead,
			Codenames: caps(ContentTypeCredential, ActionView),
		},

		// ── Job template roles ─────────────────────────────────────────────
		{
			Name: "Job Template Admin", Description: "Manage all aspects of the job template.",
			ContentType: ContentTypeJobTemplate, RoleField: RoleFieldAdmin,
			Codenames: caps(ContentTypeJobTemplate, ActionView, ActionChange, ActionDelete, ActionManage, ActionExecute),
		},
		{
			Name: "Job Template Execute", Description: "Execute the job template.",
			ContentType: ContentTypeJobTemplate, RoleField: RoleFieldExecute,
			Codenames: caps(ContentTypeJobTemplate, ActionExecute, ActionView),
		},
		{
			Name: "Job Template Read", Description: "View the job template.",
			ContentType: ContentTypeJobTemplate, RoleField: RoleFieldRead,
			Codenames: caps(ContentTypeJobTemplate, ActionView),
		},

		// ── Workflow template roles ────────────────────────────────────────
		{
			Name: "Workflow Template Admin", Description: "Manage all aspects of the workflow template.",
			ContentType: ContentTypeWorkflowTemplate, RoleField: RoleFieldAdmin,
			Codenames: caps(ContentTypeWorkflowTemplate, ActionView, ActionChange, ActionDelete, ActionManage, ActionExecute),
		},
		{
			Name: "Workflow Template Execute", Description: "Launch the workflow template.",
			ContentType: ContentTypeWorkflowTemplate, RoleField: RoleFieldExecute,
			Codenames: caps(ContentTypeWorkflowTemplate, ActionExecute, ActionView),
		},
		{
			Name: "Workflow Template Approve", Description: "Approve or deny the workflow's approval nodes.",
			ContentType: ContentTypeWorkflowTemplate, RoleField: RoleFieldApproval,
			Codenames: caps(ContentTypeWorkflowTemplate, ActionApprove, ActionView),
		},
		{
			Name: "Workflow Template Read", Description: "View the workflow template.",
			ContentType: ContentTypeWorkflowTemplate, RoleField: RoleFieldRead,
			Codenames: caps(ContentTypeWorkflowTemplate, ActionView),
		},

		// ── Team roles ─────────────────────────────────────────────────────
		{
			Name: "Team Admin", Description: "Manage all aspects of the team.",
			ContentType: ContentTypeTeam, RoleField: RoleFieldAdmin,
			Codenames: caps(ContentTypeTeam, ActionView, ActionChange, ActionDelete, ActionManage),
		},
		{
			Name: "Team Member", Description: "Belong to the team.",
			ContentType: ContentTypeTeam, RoleField: RoleFieldMember,
			Codenames: caps(ContentTypeTeam, ActionView),
		},
		{
			Name: "Team Read", Description: "View the team.",
			ContentType: ContentTypeTeam, RoleField: RoleFieldRead,
			Codenames: caps(ContentTypeTeam, ActionView),
		},
	}
}
