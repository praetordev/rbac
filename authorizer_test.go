package rbac

import "testing"

// TestCheckCapabilityDefined guards the shared Can contract: a declared (content_type,
// action) pair is accepted; an undefined one is a programming error surfaced as an error
// (→ 500), never a silent allow or deny.
func TestCheckCapabilityDefined(t *testing.T) {
	valid := []struct {
		ct ContentType
		a  Action
	}{
		{ContentTypeInventory, ActionView},
		{ContentTypeInventory, ActionChange},
		{ContentTypeJobTemplate, ActionExecute},
		{ContentTypeOrganization, ActionManage},
	}
	for _, c := range valid {
		if err := checkCapabilityDefined(c.ct, c.a); err != nil {
			t.Errorf("checkCapabilityDefined(%s, %s) = %v, want nil", c.ct, c.a, err)
		}
	}

	invalid := []struct {
		ct ContentType
		a  Action
	}{
		{ContentTypeOrganization, ActionExecute}, // org has no execute
		{ContentTypeCredential, ActionExecute},
		{ContentType("bogus"), ActionView},
	}
	for _, c := range invalid {
		if err := checkCapabilityDefined(c.ct, c.a); err == nil {
			t.Errorf("checkCapabilityDefined(%s, %s) = nil, want error", c.ct, c.a)
		}
	}
}
