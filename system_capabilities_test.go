package rbac

import "testing"

// TestCrossCatalogCodenamesUnique guards issue #130: content-type codenames
// (PermissionCatalog) and system codenames (SystemPermissionCatalog) share one flat
// namespace. A future content type — e.g. a "user" type generating manage_user — would
// collide with the system capability CapManageUser. The per-catalog well-formed tests
// check duplicates only WITHIN each catalog, so this asserts uniqueness ACROSS both.
func TestCrossCatalogCodenamesUnique(t *testing.T) {
	seen := map[string]string{} // codename -> originating catalog
	check := func(catalog string, codename string) {
		if prior, dup := seen[codename]; dup {
			t.Errorf("codename %q appears in both %s and %s catalogs", codename, prior, catalog)
			return
		}
		seen[codename] = catalog
	}
	for _, p := range PermissionCatalog() {
		check("content-type", p.Codename)
	}
	for _, p := range SystemPermissionCatalog() {
		check("system", p.Codename)
	}
}

// TestIsSystemCapability covers the exported predicate (issue #128).
func TestIsSystemCapability(t *testing.T) {
	for _, c := range []string{CapManageUser, CapViewActivityStream, CapManageExecutionPack, CapManageCredentialType, CapManageEventSource} {
		if !IsSystemCapability(c) {
			t.Errorf("IsSystemCapability(%q) = false, want true", c)
		}
	}
	for _, c := range []string{
		Codename(ContentTypeInventory, ActionChange), // a content-type capability
		Codename(ContentTypeOrganization, ActionManage),
		"manage_widget", // unknown
		"",
	} {
		if IsSystemCapability(c) {
			t.Errorf("IsSystemCapability(%q) = true, want false", c)
		}
	}
}

// TestSystemCapabilitiesIn covers the guard helper: it extracts exactly the system
// capabilities from a mixed codename list, preserving order and duplicates.
func TestSystemCapabilitiesIn(t *testing.T) {
	in := []string{
		Codename(ContentTypeInventory, ActionView),
		CapManageUser,
		Codename(ContentTypeProject, ActionUse),
		CapViewActivityStream,
		CapManageUser, // duplicate preserved
	}
	got := SystemCapabilitiesIn(in)
	want := []string{CapManageUser, CapViewActivityStream, CapManageUser}
	if len(got) != len(want) {
		t.Fatalf("SystemCapabilitiesIn = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("SystemCapabilitiesIn[%d] = %q, want %q", i, got[i], want[i])
		}
	}
	if SystemCapabilitiesIn([]string{Codename(ContentTypeInventory, ActionView)}) != nil {
		t.Error("SystemCapabilitiesIn with no system caps should return nil")
	}
}

// TestManagedScopedRolesExcludeSystemCapabilities is the invariant #128 protects: system
// capabilities must live only on the global singleton roles. Every object/org-scoped
// managed role must therefore confer none — otherwise a scoped grant would leak a
// global-only authority.
func TestManagedScopedRolesExcludeSystemCapabilities(t *testing.T) {
	sawGlobalWithSystemCap := false
	for _, mr := range ManagedRoles() {
		leaked := SystemCapabilitiesIn(mr.Codenames)
		if mr.Singleton == "" {
			if len(leaked) > 0 {
				t.Errorf("scoped managed role %q confers system capabilities %v", mr.Name, leaked)
			}
			continue
		}
		if len(leaked) > 0 {
			sawGlobalWithSystemCap = true
		}
	}
	// Sanity: the global roles DO carry system capabilities, so the test above is actually
	// exercising the predicate rather than trivially passing on an empty catalog.
	if !sawGlobalWithSystemCap {
		t.Error("expected at least one global singleton role to confer a system capability")
	}
}
