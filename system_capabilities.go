package rbac

// ── System (global-scope-only) capabilities ─────────────────────────────────────
//
// These are the administrative authorities that the legacy is_superuser /
// is_system_auditor flags used to gate, expressed as capability codenames so
// enforcement no longer reads the flags (RBAC decoupling, step 3).
//
// Unlike the polymorphic content-type capabilities (PermissionCatalog), a system
// capability is only ever meaningful at GLOBAL scope: it is granted to the System
// Administrator managed role (and, for the read-only ones, System Auditor) and is
// deliberately NOT part of everyCodename(), so it never attaches to an
// organization role. cmd/migrator seeds SystemPermissionCatalog() into
// dab_permissions alongside PermissionCatalog(); enforcement checks them via
// Authorizer.CanGlobal.

const (
	// CapManageUser gates user administration: create/update/delete users, and
	// administering any user's API tokens.
	CapManageUser = "manage_user"
	// CapViewActivityStream gates reading the audit log (System Administrator and
	// System Auditor).
	CapViewActivityStream = "view_activitystream"
	// CapManageExecutionPack gates managing execution packs (the pushable runtimes)
	// and seeing their build triggers.
	CapManageExecutionPack = "manage_executionpack"
	// CapManageCredentialType gates managing credential types.
	CapManageCredentialType = "manage_credentialtype"
	// CapManageEventSource gates managing event sources and rules.
	CapManageEventSource = "manage_eventsource"
)

// systemPermission is one system capability with its dab_permissions metadata. The
// content_type/action columns are descriptive only — enforcement matches on codename.
type systemPermission struct {
	codename    string
	contentType string
	action      string
	label       string
}

// systemPermissions is the ordered declaration of every system capability.
var systemPermissions = []systemPermission{
	{CapManageUser, "user", "manage", "Manage users"},
	{CapViewActivityStream, "activity_stream", "view", "View activity stream"},
	{CapManageExecutionPack, "execution_pack", "manage", "Manage execution packs"},
	{CapManageCredentialType, "credential_type", "manage", "Manage credential types"},
	{CapManageEventSource, "event_source", "manage", "Manage event sources"},
}

// SystemPermissionCatalog returns the system capabilities to seed into
// dab_permissions. IDs/CreatedAt are unset (assigned by the database).
func SystemPermissionCatalog() []DABPermission {
	out := make([]DABPermission, 0, len(systemPermissions))
	for _, p := range systemPermissions {
		name := p.label
		out = append(out, DABPermission{
			Codename:    p.codename,
			ContentType: p.contentType,
			Action:      p.action,
			Name:        &name,
		})
	}
	return out
}

// systemCodenameSet indexes systemPermissions by codename for O(1) membership tests.
var systemCodenameSet = func() map[string]struct{} {
	m := make(map[string]struct{}, len(systemPermissions))
	for _, p := range systemPermissions {
		m[p.codename] = struct{}{}
	}
	return m
}()

// IsSystemCapability reports whether codename names a global-scope-only system capability
// (manage_user, view_activitystream, …). Such a capability is meaningful only at GLOBAL
// scope, so a custom RoleDefinition that bundles one at object/team scope is a
// privilege-escalation bug the caller must reject. Content-type capabilities and unknown
// codenames return false.
func IsSystemCapability(codename string) bool {
	_, ok := systemCodenameSet[codename]
	return ok
}

// SystemCapabilitiesIn returns the system capabilities present in codenames — the ones a
// non-global (object/team-scoped) role must not confer. A caller validating a custom,
// object-scoped RoleDefinition should reject the definition when this is non-empty. The
// result follows input order and preserves duplicates; it is nil when there are none.
func SystemCapabilitiesIn(codenames []string) []string {
	var out []string
	for _, c := range codenames {
		if IsSystemCapability(c) {
			out = append(out, c)
		}
	}
	return out
}

// systemAdminCodenames returns every system capability — the set granted to the
// System Administrator managed role.
func systemAdminCodenames() []string {
	out := make([]string, 0, len(systemPermissions))
	for _, p := range systemPermissions {
		out = append(out, p.codename)
	}
	return out
}

// systemAuditorCodenames returns the read-only system capabilities — the set
// granted to the System Auditor managed role.
func systemAuditorCodenames() []string {
	return []string{CapViewActivityStream}
}
