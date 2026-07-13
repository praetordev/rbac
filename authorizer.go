package rbac

import (
	"context"
	"fmt"
)

// This file defines the Policy Decision Point (PDP) contract for the capability
// RBAC engine. The capability store implements Authorizer; callers depend on this
// interface, never on the concrete store — so the decision (this package) and its
// enforcement (HTTP handlers) stay separable.

// Object identifies a single resource instance in an authorization question.
type Object struct {
	Type ContentType
	ID   int64
}

// Obj is a terse constructor for an Object.
func Obj(t ContentType, id int64) Object { return Object{Type: t, ID: id} }

// Subject is the authenticated principal an authorization decision is made for.
// Handlers receive a Subject and pass it to the Authorizer; policy lives in the
// capability model, never in flags on the subject.
type Subject struct {
	UserID int64
}

// NewSubject builds a Subject for the given user.
func NewSubject(userID int64) Subject {
	return Subject{UserID: userID}
}

// Authorizer is the policy decision point. Callers express intent as a
// capability — an (action, object) pair or a raw codename — and never as a role
// name. Every method is deny-by-default and returns (bool, error) so a database
// failure surfaces as a 500, never a silent allow.
type Authorizer interface {
	// Can reports whether sub may perform action on obj. The codename checked is
	// Codename(obj.Type, action); an (obj.Type, action) pair outside the catalog
	// is a programming error and returns a non-nil error.
	Can(ctx context.Context, sub Subject, action Action, obj Object) (bool, error)

	// CanCodename reports whether sub holds an arbitrary codename ON obj. This is
	// the cross-type primitive: e.g. "may create a project inside THIS org" is
	// CanCodename(sub, "add_project", Obj(organization, orgID)) — the codename's
	// content type (project) differs from the object's (organization).
	CanCodename(ctx context.Context, sub Subject, codename string, obj Object) (bool, error)

	// CanGlobal reports whether sub holds codename with global (system-role)
	// scope, independent of any object.
	CanGlobal(ctx context.Context, sub Subject, codename string) (bool, error)

	// VisibleIDs returns every object id of t on which sub holds action — the
	// list-filtering primitive. It unifies the global and scoped tiers so callers
	// never branch on "sees everything".
	VisibleIDs(ctx context.Context, sub Subject, action Action, t ContentType) ([]int64, error)
}

// checkCapabilityDefined enforces the Can contract: an (action, contentType) pair
// outside the catalog is a programming error and must surface as an error, never a
// silent allow or deny.
func checkCapabilityDefined(ct ContentType, action Action) error {
	if IsValidCapability(ct, action) {
		return nil
	}
	return fmt.Errorf("capability %q is not defined for content type %q", action, ct)
}
