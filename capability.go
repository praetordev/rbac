package rbac

import (
	"strings"
	"time"
)

// ContentType is the type of object a capability applies to. Its values are defined
// by the consumer's vocabulary (see Catalog); the engine treats it as an opaque
// identifier and has no built-in content types.
type ContentType string

// Action is an atomic verb a capability grants on a content type. Its values are
// defined by the consumer's vocabulary.
type Action string

// Codename is the canonical "<action>_<content_type>" identifier for a capability,
// e.g. Codename("inventory", "view") == "view_inventory".
func Codename(ct ContentType, a Action) string {
	return string(a) + "_" + string(ct)
}

// DABPermission is one atomic capability (a row of dab_permissions).
type DABPermission struct {
	ID          int64     `db:"id" json:"id"`
	Codename    string    `db:"codename" json:"codename"`
	ContentType string    `db:"content_type" json:"content_type"`
	Action      string    `db:"action" json:"action"`
	Name        *string   `db:"name" json:"name,omitempty"`
	CreatedAt   time.Time `db:"created_at" json:"created_at"`
}

// RoleDefinition is a named bundle of capabilities (a row of role_definitions).
// Managed definitions are seeded built-ins; custom ones are operator-defined.
type RoleDefinition struct {
	ID          int64     `db:"id" json:"id"`
	Name        string    `db:"name" json:"name"`
	Description string    `db:"description" json:"description"`
	Managed     bool      `db:"managed" json:"managed"`
	ContentType *string   `db:"content_type" json:"content_type,omitempty"`
	CreatedAt   time.Time `db:"created_at" json:"created_at"`
	ModifiedAt  time.Time `db:"modified_at" json:"modified_at"`
}

// defaultLabel builds a human-readable permission name, e.g.
// ("execute", "job_template") -> "Execute job template".
func defaultLabel(a Action, ct ContentType) string {
	verb := string(a)
	if verb != "" {
		verb = strings.ToUpper(verb[:1]) + verb[1:]
	}
	noun := strings.ReplaceAll(string(ct), "_", " ")
	return strings.TrimSpace(verb + " " + noun)
}
