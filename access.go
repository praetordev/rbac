package rbac

import (
	"context"

	"github.com/jmoiron/sqlx"
)

// AccessChecker holds the DB handle for object→organization resolution used by the
// access handlers' org fence. Authorization itself runs on the capability model
// (CapabilityStore); this is a resolution helper, not a decision point.
type AccessChecker struct {
	DB *sqlx.DB
}

// NewAccessChecker creates a new AccessChecker instance.
func NewAccessChecker(db *sqlx.DB) *AccessChecker {
	return &AccessChecker{DB: db}
}

// contentTables maps a content type to the physical table holding its rows, so an
// object's organization can be resolved without user-supplied identifiers.
var contentTables = map[ContentType]string{
	ContentTypeOrganization:     "organizations",
	ContentTypeTeam:             "teams",
	ContentTypeProject:          "projects",
	ContentTypeInventory:        "inventories",
	ContentTypeJobTemplate:      "job_templates",
	ContentTypeWorkflowTemplate: "workflow_templates",
	ContentTypeCredential:       "credentials",
}

// OrgForContent returns the organization id an object belongs to. An organization is its
// own org; other resource types resolve via their organization_id column (table from
// contentTables, never user input, so the interpolation is safe).
func (a *AccessChecker) OrgForContent(ctx context.Context, contentType ContentType, objectID int64) (int64, bool) {
	if contentType == ContentTypeOrganization {
		return objectID, true
	}
	table, ok := contentTables[contentType]
	if !ok {
		return 0, false
	}
	var org int64
	if err := a.DB.GetContext(ctx, &org, "SELECT organization_id FROM "+table+" WHERE id = $1", objectID); err != nil {
		return 0, false
	}
	return org, true
}
