package rbac

import (
	"strings"
	"time"
)

// ── DAB-style capability model (Gitea #94, epic #93) ────────────────────────────
//
// This file is the single source of truth for the capability CATALOG: the set of
// atomic (content_type, action) permissions the system understands. cmd/migrator
// seeds dab_permissions from PermissionCatalog() on every run (idempotent), the same
// way credential_types are seeded, so the vocabulary lives in code rather than in a
// migration comment.
//
// A capability is one (ContentType, Action). Its codename is "<action>_<content_type>"
// e.g. "view_inventory", "execute_job_template". A RoleDefinition (later phases) is a
// named bundle of these; that is what an operator — or an LDAP group mapping — grants.
//
// This is additive: it does not replace the legacy RoleField/action checks yet. #95
// mirrors the legacy roles as managed RoleDefinitions; #97 switches enforcement over.

// Action is an atomic verb a capability grants on a content type.
type Action string

const (
	ActionView    Action = "view"    // read the object
	ActionAdd     Action = "add"     // create objects of this type (held at org scope)
	ActionChange  Action = "change"  // modify the object's configuration
	ActionDelete  Action = "delete"  // delete the object
	ActionManage  Action = "manage"  // administer the object (the actAdmin check maps here)
	ActionUse     Action = "use"     // reference in a job template (project/inventory/credential)
	ActionExecute Action = "execute" // launch (job template / workflow template)
	ActionUpdate  Action = "update"  // SCM update / inventory-source sync
	ActionAdhoc   Action = "adhoc"   // run ad-hoc commands (inventory; reserved, see RoleFieldAdhoc)
	ActionApprove Action = "approve" // approve/deny a workflow approval node
)

// capabilityContentTypeOrder fixes the iteration order so seeding and API output are
// deterministic across runs.
var capabilityContentTypeOrder = []ContentType{
	ContentTypeOrganization,
	ContentTypeTeam,
	ContentTypeProject,
	ContentTypeInventory,
	ContentTypeCredential,
	ContentTypeJobTemplate,
	ContentTypeWorkflowTemplate,
}

// capabilityCatalog declares which actions are valid on each content type. Only these
// (content_type, action) pairs are legal capabilities; anything else is rejected by
// IsValidCapability. Actions within a type are listed CRUD-first, then specials, to
// keep seeded rows in a readable order.
var capabilityCatalog = map[ContentType][]Action{
	ContentTypeOrganization:     {ActionView, ActionAdd, ActionChange, ActionDelete, ActionManage},
	ContentTypeTeam:             {ActionView, ActionAdd, ActionChange, ActionDelete, ActionManage},
	ContentTypeProject:          {ActionView, ActionAdd, ActionChange, ActionDelete, ActionManage, ActionUse, ActionUpdate},
	ContentTypeInventory:        {ActionView, ActionAdd, ActionChange, ActionDelete, ActionManage, ActionUse, ActionUpdate, ActionAdhoc},
	ContentTypeCredential:       {ActionView, ActionAdd, ActionChange, ActionDelete, ActionManage, ActionUse},
	ContentTypeJobTemplate:      {ActionView, ActionAdd, ActionChange, ActionDelete, ActionManage, ActionExecute},
	ContentTypeWorkflowTemplate: {ActionView, ActionAdd, ActionChange, ActionDelete, ActionManage, ActionExecute, ActionApprove},
}

// DABPermission is one atomic capability (a row of dab_permissions).
type DABPermission struct {
	ID          int64     `db:"id" json:"id"`
	Codename    string    `db:"codename" json:"codename"`
	ContentType string    `db:"content_type" json:"content_type"`
	Action      string    `db:"action" json:"action"`
	Name        *string   `db:"name" json:"name,omitempty"`
	CreatedAt   time.Time `db:"created_at" json:"created_at"`
}

// RoleDefinition is a named bundle of capabilities (a row of role_definitions).
// Managed definitions mirror the legacy fixed roles; custom ones are operator-defined.
type RoleDefinition struct {
	ID          int64     `db:"id" json:"id"`
	Name        string    `db:"name" json:"name"`
	Description string    `db:"description" json:"description"`
	Managed     bool      `db:"managed" json:"managed"`
	ContentType *string   `db:"content_type" json:"content_type,omitempty"`
	CreatedAt   time.Time `db:"created_at" json:"created_at"`
	ModifiedAt  time.Time `db:"modified_at" json:"modified_at"`
}

// Codename returns the canonical "<action>_<content_type>" identifier for a capability.
func Codename(ct ContentType, a Action) string {
	return string(a) + "_" + string(ct)
}

// IsValidCapability reports whether (ct, action) is a declared capability in the catalog.
func IsValidCapability(ct ContentType, a Action) bool {
	for _, cand := range capabilityCatalog[ct] {
		if cand == a {
			return true
		}
	}
	return false
}

// CapabilityContentTypes returns the content types that have capabilities, in catalog order.
func CapabilityContentTypes() []ContentType {
	out := make([]ContentType, len(capabilityContentTypeOrder))
	copy(out, capabilityContentTypeOrder)
	return out
}

// PermissionCatalog returns the full, deterministically-ordered list of capabilities to
// seed into dab_permissions. IDs/CreatedAt are unset (assigned by the database).
func PermissionCatalog() []DABPermission {
	var out []DABPermission
	for _, ct := range capabilityContentTypeOrder {
		for _, a := range capabilityCatalog[ct] {
			name := capabilityLabel(a, ct)
			out = append(out, DABPermission{
				Codename:    Codename(ct, a),
				ContentType: string(ct),
				Action:      string(a),
				Name:        &name,
			})
		}
	}
	return out
}

// capabilityLabel builds a human-readable name, e.g. (execute, job_template) ->
// "Execute job template".
func capabilityLabel(a Action, ct ContentType) string {
	verb := string(a)
	verb = strings.ToUpper(verb[:1]) + verb[1:]
	noun := strings.ReplaceAll(string(ct), "_", " ")
	return verb + " " + noun
}
