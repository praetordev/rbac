package rbac

import (
	"strings"
	"testing"
)

func catalogSet() map[string]bool {
	set := map[string]bool{}
	for _, p := range PermissionCatalog() {
		set[p.Codename] = true
	}
	return set
}

// Every codename a managed role references must be a real catalog capability, else the
// seeder would silently attach nothing.
func TestManagedRolesReferenceRealCapabilities(t *testing.T) {
	cat := catalogSet()
	for _, mr := range ManagedRoles() {
		if len(mr.Codenames) == 0 {
			t.Errorf("managed role %q has no codenames", mr.Name)
		}
		seen := map[string]bool{}
		for _, cn := range mr.Codenames {
			if !cat[cn] {
				t.Errorf("managed role %q references unknown codename %q", mr.Name, cn)
			}
			if seen[cn] {
				t.Errorf("managed role %q lists %q twice", mr.Name, cn)
			}
			seen[cn] = true
		}
	}
}

func TestManagedRoleNamesUnique(t *testing.T) {
	seen := map[string]bool{}
	for _, mr := range ManagedRoles() {
		if seen[mr.Name] {
			t.Errorf("duplicate managed role name %q", mr.Name)
		}
		seen[mr.Name] = true
	}
}

// A managed role mirrors either a legacy object/org role_field or a singleton — exactly one.
func TestManagedRoleIdentityExclusive(t *testing.T) {
	for _, mr := range ManagedRoles() {
		isSingleton := mr.Singleton != ""
		isObject := mr.RoleField != "" && mr.ContentType != ""
		if isSingleton == isObject {
			t.Errorf("managed role %q must be exactly one of singleton/object (singleton=%q ct=%q field=%q)",
				mr.Name, mr.Singleton, mr.ContentType, mr.RoleField)
		}
	}
}

func find(t *testing.T, name string) ManagedRole {
	t.Helper()
	for _, mr := range ManagedRoles() {
		if mr.Name == name {
			return mr
		}
	}
	t.Fatalf("managed role %q not found", name)
	return ManagedRole{}
}

func has(mr ManagedRole, codename string) bool {
	for _, cn := range mr.Codenames {
		if cn == codename {
			return true
		}
	}
	return false
}

// System / Organization admin grant the full catalog; auditors are view-only.
func TestAdminAndAuditorShape(t *testing.T) {
	full := len(PermissionCatalog())
	for _, name := range []string{"System Administrator", "Organization Admin"} {
		if got := len(find(t, name).Codenames); got != full {
			t.Errorf("%s should grant all %d capabilities, has %d", name, full, got)
		}
	}
	for _, name := range []string{"System Auditor", "Organization Auditor"} {
		for _, cn := range find(t, name).Codenames {
			if !strings.HasPrefix(cn, string(ActionView)+"_") {
				t.Errorf("%s is not read-only: has %q", name, cn)
			}
		}
	}
}

// Managing a workflow is not approving it (mirrors 000049): neither the object-level nor
// the org-level workflow admin may approve.
func TestWorkflowAdminExcludesApprove(t *testing.T) {
	approve := Codename(ContentTypeWorkflowTemplate, ActionApprove)
	for _, name := range []string{"Workflow Template Admin", "Organization Workflow Admin"} {
		if has(find(t, name), approve) {
			t.Errorf("%s must not include %q", name, approve)
		}
	}
	if !has(find(t, "Workflow Template Approve"), approve) {
		t.Error("Workflow Template Approve must include the approve capability")
	}
}

// add_* is an org-scoped capability; object-level admin roles must not carry it.
func TestObjectAdminsExcludeAdd(t *testing.T) {
	for _, mr := range ManagedRoles() {
		if mr.Singleton != "" || mr.ContentType == ContentTypeOrganization {
			continue
		}
		for _, cn := range mr.Codenames {
			if strings.HasPrefix(cn, string(ActionAdd)+"_") {
				t.Errorf("object-level role %q must not carry an add_* capability (%q)", mr.Name, cn)
			}
		}
	}
}

// The manage capability (what actAdmin maps to in #97) must be present on every
// object-level Admin role, or an admin would fail the admin check under the new model.
func TestObjectAdminsIncludeManage(t *testing.T) {
	cases := map[string]ContentType{
		"Project Admin":           ContentTypeProject,
		"Inventory Admin":         ContentTypeInventory,
		"Credential Admin":        ContentTypeCredential,
		"Job Template Admin":      ContentTypeJobTemplate,
		"Workflow Template Admin": ContentTypeWorkflowTemplate,
		"Team Admin":              ContentTypeTeam,
	}
	for name, ct := range cases {
		if !has(find(t, name), Codename(ct, ActionManage)) {
			t.Errorf("%s must include %q", name, Codename(ct, ActionManage))
		}
	}
	// System / Organization admin carry the full catalog, so every manage_* too.
	for _, name := range []string{"System Administrator", "Organization Admin"} {
		for _, ct := range CapabilityContentTypes() {
			if !has(find(t, name), Codename(ct, ActionManage)) {
				t.Errorf("%s missing %q", name, Codename(ct, ActionManage))
			}
		}
	}
}

// Every legacy object role_field that enforcement checks has a managed mirror, so no
// current grant loses meaning under the capability model.
func TestLegacyObjectRolesCovered(t *testing.T) {
	want := map[ContentType][]RoleField{
		ContentTypeProject:          {RoleFieldAdmin, RoleFieldUse, RoleFieldUpdate, RoleFieldRead},
		ContentTypeInventory:        {RoleFieldAdmin, RoleFieldUse, RoleFieldUpdate, RoleFieldAdhoc, RoleFieldRead},
		ContentTypeCredential:       {RoleFieldAdmin, RoleFieldUse, RoleFieldRead},
		ContentTypeJobTemplate:      {RoleFieldAdmin, RoleFieldExecute, RoleFieldRead},
		ContentTypeWorkflowTemplate: {RoleFieldAdmin, RoleFieldExecute, RoleFieldApproval, RoleFieldRead},
		ContentTypeTeam:             {RoleFieldAdmin, RoleFieldMember, RoleFieldRead},
	}
	covered := map[ContentType]map[RoleField]bool{}
	for _, mr := range ManagedRoles() {
		if mr.Singleton != "" {
			continue
		}
		if covered[mr.ContentType] == nil {
			covered[mr.ContentType] = map[RoleField]bool{}
		}
		covered[mr.ContentType][mr.RoleField] = true
	}
	for ct, fields := range want {
		for _, f := range fields {
			if !covered[ct][f] {
				t.Errorf("no managed role mirrors legacy %s/%s", ct, f)
			}
		}
	}
}
