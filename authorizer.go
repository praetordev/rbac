package rbac

import (
	"context"
	"fmt"
)

// This file defines the Policy Decision Point (PDP) contract for Praetor's
// capability RBAC. The capability store (services/api) implements Authorizer;
// handlers depend on this interface, never on the concrete store — so the
// decision (this package) and its enforcement (HTTP handlers) are separable,
// and the legacy is_superuser bypass lives in one decorator instead of being
// scattered across every handler.
//
// See docs/coupling-decomposition-plan.md and the RBAC decoupling plan.

// Object identifies a single resource instance in an authorization question.
type Object struct {
	Type ContentType
	ID   int64
}

// Obj is a terse constructor for an Object.
func Obj(t ContentType, id int64) Object { return Object{Type: t, ID: id} }

// Subject is the authenticated principal an authorization decision is made for.
//
// The legacy system flags are UNEXPORTED on purpose: only decorators in this
// package may consult them. Handler and service code receives a Subject and can
// pass it to the Authorizer, but can never branch on `sub.legacySuperuser` —
// that is what keeps role/flag concepts out of business logic.
type Subject struct {
	UserID int64

	legacySuperuser bool
	legacyAuditor   bool
}

// NewSubject builds a Subject. It is called at the enforcement boundary (the
// auth-derived UserContext), the one place the legacy flags are still read.
func NewSubject(userID int64, legacySuperuser, legacyAuditor bool) Subject {
	return Subject{UserID: userID, legacySuperuser: legacySuperuser, legacyAuditor: legacyAuditor}
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

// checkCapabilityDefined enforces the shared Can contract: an (action, contentType)
// pair outside the catalog is a programming error and must surface as an error, never a
// silent allow or deny. Both Can implementations — the store and the legacy decorator —
// call this so the contract cannot drift between them.
func checkCapabilityDefined(ct ContentType, action Action) error {
	if IsValidCapability(ct, action) {
		return nil
	}
	return fmt.Errorf("capability %q is not defined for content type %q", action, ct)
}

// globalLister is the optional capability the legacy decorator needs to answer
// VisibleIDs for a break-glass superuser (who has no per-object rows): list
// every id of a type. The capability store satisfies it via AllIDsOfType.
type globalLister interface {
	AllIDsOfType(ctx context.Context, ct ContentType) ([]int64, error)
}

// WithLegacySystemFlags wraps an Authorizer with the dual-run bypass: a legacy
// is_superuser holds every capability on every object. This is the ONLY place
// the flag is honoured — remove this one wrap (in wiring) once superusers are
// backfilled to the global System Administrator role, and no call site changes.
//
// The system-auditor flag is deliberately NOT bypassed here: auditor reads
// already route through the capability model (the managed System Auditor role
// grants view globally), so honouring the flag would diverge from, not preserve,
// current behaviour. It folds in when the remaining direct IsSystemAuditor
// handler branches migrate to VisibleIDs.
func WithLegacySystemFlags(next Authorizer) Authorizer {
	return &legacyFlags{next: next}
}

type legacyFlags struct {
	next Authorizer
}

func (l *legacyFlags) Can(ctx context.Context, sub Subject, action Action, obj Object) (bool, error) {
	// Validate BEFORE the bypass: a superuser checking an undefined capability is a
	// programming error and must still error, not be silently allowed. Superusers are
	// exactly who test new code, so swallowing it here hides the bug from them.
	if err := checkCapabilityDefined(obj.Type, action); err != nil {
		return false, wrap("legacyFlags.Can", err)
	}
	if sub.legacySuperuser {
		return true, nil
	}
	return l.next.Can(ctx, sub, action, obj)
}

func (l *legacyFlags) CanCodename(ctx context.Context, sub Subject, codename string, obj Object) (bool, error) {
	if sub.legacySuperuser {
		return true, nil
	}
	return l.next.CanCodename(ctx, sub, codename, obj)
}

func (l *legacyFlags) CanGlobal(ctx context.Context, sub Subject, codename string) (bool, error) {
	if sub.legacySuperuser {
		return true, nil
	}
	return l.next.CanGlobal(ctx, sub, codename)
}

func (l *legacyFlags) VisibleIDs(ctx context.Context, sub Subject, action Action, t ContentType) ([]int64, error) {
	if sub.legacySuperuser {
		if gl, ok := l.next.(globalLister); ok {
			return gl.AllIDsOfType(ctx, t)
		}
	}
	return l.next.VisibleIDs(ctx, sub, action, t)
}
