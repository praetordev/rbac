package rbac

import "testing"

// sampleCatalog is a small, domain-neutral vocabulary used across the root-package tests.
func sampleCatalog() *Catalog {
	return NewCatalog().
		Type("widget", "view", "change", "manage").
		Type("gadget", "view", "manage").
		System("manage_user", "user", "manage", "Manage users").
		System("view_audit", "audit", "view", "View audit log")
}

func TestCatalogValidAndOrder(t *testing.T) {
	cat := sampleCatalog()

	if !cat.IsValid("widget", "change") {
		t.Error("widget:change should be valid")
	}
	if cat.IsValid("gadget", "change") {
		t.Error("gadget:change should be invalid")
	}
	if cat.IsValid("bogus", "view") {
		t.Error("unknown content type should be invalid")
	}

	// ContentTypes preserves declaration order.
	got := cat.ContentTypes()
	want := []ContentType{"widget", "gadget"}
	if len(got) != len(want) {
		t.Fatalf("ContentTypes = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("ContentTypes[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}

func TestCatalogPermissionsWellFormed(t *testing.T) {
	cat := sampleCatalog()
	perms := cat.Permissions()
	if len(perms) == 0 {
		t.Fatal("permissions empty")
	}
	seen := map[string]bool{}
	for _, p := range perms {
		if p.Codename != p.Action+"_"+p.ContentType {
			t.Errorf("codename %q is not <action>_<content_type>", p.Codename)
		}
		if seen[p.Codename] {
			t.Errorf("duplicate codename %q", p.Codename)
		}
		seen[p.Codename] = true
		if p.Name == nil || *p.Name == "" {
			t.Errorf("codename %q has no display name", p.Codename)
		}
		if !cat.IsValid(ContentType(p.ContentType), Action(p.Action)) {
			t.Errorf("Permissions emitted %q but IsValid rejects it", p.Codename)
		}
	}
}

func TestCatalogPermissionsDeterministic(t *testing.T) {
	a, b := sampleCatalog().Permissions(), sampleCatalog().Permissions()
	if len(a) != len(b) {
		t.Fatalf("permission count varies: %d vs %d", len(a), len(b))
	}
	for i := range a {
		if a[i].Codename != b[i].Codename {
			t.Fatalf("order not stable at %d: %q vs %q", i, a[i].Codename, b[i].Codename)
		}
	}
}

// Content-type and system codenames share one flat namespace; adding a "user" content
// type that generated manage_user would collide with the system capability. This guards
// uniqueness across BOTH sets, which the per-set checks miss.
func TestCatalogCrossNamespaceUnique(t *testing.T) {
	cat := sampleCatalog()
	seen := map[string]string{}
	check := func(kind, codename string) {
		if prior, dup := seen[codename]; dup {
			t.Errorf("codename %q appears in both %s and %s", codename, prior, kind)
			return
		}
		seen[codename] = kind
	}
	for _, p := range cat.Permissions() {
		check("content-type", p.Codename)
	}
	for _, p := range cat.SystemPermissions() {
		check("system", p.Codename)
	}
}

func TestCatalogSystemCapabilities(t *testing.T) {
	cat := sampleCatalog()
	for _, c := range []string{"manage_user", "view_audit"} {
		if !cat.IsSystemCapability(c) {
			t.Errorf("IsSystemCapability(%q) = false, want true", c)
		}
	}
	for _, c := range []string{Codename("widget", "manage"), "bogus", ""} {
		if cat.IsSystemCapability(c) {
			t.Errorf("IsSystemCapability(%q) = true, want false", c)
		}
	}

	in := []string{Codename("widget", "view"), "manage_user", Codename("gadget", "view"), "view_audit", "manage_user"}
	got := cat.SystemCapabilitiesIn(in)
	want := []string{"manage_user", "view_audit", "manage_user"} // order preserved, dupes kept
	if len(got) != len(want) {
		t.Fatalf("SystemCapabilitiesIn = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("SystemCapabilitiesIn[%d] = %q, want %q", i, got[i], want[i])
		}
	}
	if cat.SystemCapabilitiesIn([]string{Codename("widget", "view")}) != nil {
		t.Error("SystemCapabilitiesIn with no system caps should be nil")
	}
}

// Type is additive and dedupes; repeated declarations extend the action set in order.
func TestCatalogTypeDedupeAndExtend(t *testing.T) {
	cat := NewCatalog().Type("thing", "view", "view", "edit").Type("thing", "edit", "delete")
	perms := cat.Permissions()
	var actions []string
	for _, p := range perms {
		actions = append(actions, p.Action)
	}
	want := []string{"view", "edit", "delete"}
	if len(actions) != len(want) {
		t.Fatalf("actions = %v, want %v", actions, want)
	}
	for i := range want {
		if actions[i] != want[i] {
			t.Fatalf("actions[%d] = %q, want %q", i, actions[i], want[i])
		}
	}
}
