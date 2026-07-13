package rbac

import (
	"context"
	"testing"
)

// fakeAuthorizer is a stand-in PDP that records which methods the decorator delegated to
// and returns canned answers. It also satisfies globalLister for the VisibleIDs path.
type fakeAuthorizer struct {
	canCalled         bool
	canCodenameCalled bool
	canGlobalCalled   bool
	visibleCalled     bool
	allIDsCalled      bool

	result bool
	allIDs []int64
}

func (f *fakeAuthorizer) Can(ctx context.Context, sub Subject, action Action, obj Object) (bool, error) {
	f.canCalled = true
	return f.result, nil
}

func (f *fakeAuthorizer) CanCodename(ctx context.Context, sub Subject, codename string, obj Object) (bool, error) {
	f.canCodenameCalled = true
	return f.result, nil
}

func (f *fakeAuthorizer) CanGlobal(ctx context.Context, sub Subject, codename string) (bool, error) {
	f.canGlobalCalled = true
	return f.result, nil
}

func (f *fakeAuthorizer) VisibleIDs(ctx context.Context, sub Subject, action Action, t ContentType) ([]int64, error) {
	f.visibleCalled = true
	return nil, nil
}

func (f *fakeAuthorizer) AllIDsOfType(ctx context.Context, ct ContentType) ([]int64, error) {
	f.allIDsCalled = true
	return f.allIDs, nil
}

// A valid capability (in the catalog) and an invalid one (organization has no "execute").
var (
	validObj      = Obj(ContentTypeInventory, 7)
	validAction   = ActionView
	invalidObj    = Obj(ContentTypeOrganization, 3)
	invalidAction = ActionExecute
)

// TestLegacyFlags_CanValidatesBeforeBypass is issue #126: a superuser checking an
// undefined capability must get an error, not a silent (true, nil), and the wrapped
// authorizer must not be consulted.
func TestLegacyFlags_CanValidatesBeforeBypass(t *testing.T) {
	fake := &fakeAuthorizer{result: true}
	auth := WithLegacySystemFlags(fake)
	su := NewSubject(1, true, false) // superuser

	ok, err := auth.Can(context.Background(), su, invalidAction, invalidObj)
	if err == nil {
		t.Fatal("expected an error for an undefined capability, got nil (silently allowed)")
	}
	if ok {
		t.Fatal("expected ok=false for an undefined capability")
	}
	if fake.canCalled {
		t.Fatal("wrapped authorizer should not be called when the capability is invalid")
	}
}

// TestLegacyFlags_CanBypassesValidForSuperuser confirms the bypass still short-circuits a
// valid capability for a superuser without consulting the wrapped store.
func TestLegacyFlags_CanBypassesValidForSuperuser(t *testing.T) {
	fake := &fakeAuthorizer{result: false} // would deny if consulted
	auth := WithLegacySystemFlags(fake)
	su := NewSubject(1, true, false)

	ok, err := auth.Can(context.Background(), su, validAction, validObj)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !ok {
		t.Fatal("superuser should be allowed a valid capability")
	}
	if fake.canCalled {
		t.Fatal("wrapped authorizer should not be consulted for a superuser bypass")
	}
}

// TestLegacyFlags_CanDelegatesForNonSuperuser confirms a non-superuser with a valid
// capability is delegated to the wrapped authorizer, whose answer is returned verbatim.
func TestLegacyFlags_CanDelegatesForNonSuperuser(t *testing.T) {
	fake := &fakeAuthorizer{result: true}
	auth := WithLegacySystemFlags(fake)
	sub := NewSubject(1, false, false)

	ok, err := auth.Can(context.Background(), sub, validAction, validObj)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !ok {
		t.Fatal("expected the wrapped authorizer's true result")
	}
	if !fake.canCalled {
		t.Fatal("expected delegation to the wrapped authorizer")
	}
}

// TestLegacyFlags_AuditorNotBypassed confirms the system-auditor flag is deliberately NOT
// a bypass: an auditor (not superuser) delegates to the capability model like anyone else.
func TestLegacyFlags_AuditorNotBypassed(t *testing.T) {
	fake := &fakeAuthorizer{result: false}
	auth := WithLegacySystemFlags(fake)
	auditor := NewSubject(1, false, true) // auditor, not superuser

	ok, err := auth.Can(context.Background(), auditor, validAction, validObj)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ok {
		t.Fatal("auditor must not be auto-allowed; the wrapped answer (deny) should stand")
	}
	if !fake.canCalled {
		t.Fatal("auditor must delegate to the wrapped authorizer")
	}
}

// TestLegacyFlags_VisibleIDsSuperuserListsAll confirms a superuser's VisibleIDs is served
// by the globalLister (AllIDsOfType), not the per-object VisibleIDs path.
func TestLegacyFlags_VisibleIDsSuperuserListsAll(t *testing.T) {
	fake := &fakeAuthorizer{allIDs: []int64{1, 2, 3}}
	auth := WithLegacySystemFlags(fake)
	su := NewSubject(1, true, false)

	ids, err := auth.VisibleIDs(context.Background(), su, ActionView, ContentTypeInventory)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !equalInts(ids, []int64{1, 2, 3}) {
		t.Fatalf("expected all ids from AllIDsOfType, got %v", ids)
	}
	if !fake.allIDsCalled {
		t.Fatal("expected AllIDsOfType to serve the superuser list")
	}
	if fake.visibleCalled {
		t.Fatal("per-object VisibleIDs should be skipped for a superuser with a globalLister")
	}
}
