package rbac

import "testing"

// The catalog is the single source of truth seeded into dab_permissions; these guard
// its shape so a stray edit can't silently corrupt the vocabulary.

func TestPermissionCatalogWellFormed(t *testing.T) {
	catalog := PermissionCatalog()
	if len(catalog) == 0 {
		t.Fatal("catalog is empty")
	}
	seen := map[string]bool{}
	for _, p := range catalog {
		if p.Codename != p.Action+"_"+p.ContentType {
			t.Errorf("codename %q is not <action>_<content_type> for (%s,%s)", p.Codename, p.Action, p.ContentType)
		}
		if seen[p.Codename] {
			t.Errorf("duplicate codename %q", p.Codename)
		}
		seen[p.Codename] = true
		if p.Name == nil || *p.Name == "" {
			t.Errorf("codename %q has no display name", p.Codename)
		}
		if !IsValidCapability(ContentType(p.ContentType), Action(p.Action)) {
			t.Errorf("catalog emitted %q but IsValidCapability rejects it", p.Codename)
		}
	}
}

func TestPermissionCatalogDeterministic(t *testing.T) {
	a, b := PermissionCatalog(), PermissionCatalog()
	if len(a) != len(b) {
		t.Fatalf("catalog length varies: %d vs %d", len(a), len(b))
	}
	for i := range a {
		if a[i].Codename != b[i].Codename {
			t.Fatalf("catalog order not stable at %d: %q vs %q", i, a[i].Codename, b[i].Codename)
		}
	}
}

func TestIsValidCapabilityRejectsUnknown(t *testing.T) {
	if IsValidCapability(ContentTypeCredential, ActionExecute) {
		t.Error("credential:execute should not be a valid capability")
	}
	if IsValidCapability(ContentType("bogus"), ActionView) {
		t.Error("view on an unknown content type should be invalid")
	}
	if !IsValidCapability(ContentTypeJobTemplate, ActionExecute) {
		t.Error("job_template:execute should be valid")
	}
}
