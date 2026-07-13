// Package rbac is a generic, capability-based Role-Based Access Control engine.
//
// It provides the mechanism, not a vocabulary: the Authorizer decision contract and
// the capability/role model live in this package; the SQL-backed policy decision point
// lives in the postgres subpackage. The engine has no built-in content types, actions,
// or roles — a consumer declares its own vocabulary by building a Catalog, then wires a
// store:
//
//	cat := rbac.NewCatalog().
//		Type("project", "view", "change", "manage").
//		Type("inventory", "view", "change", "use").
//		System("manage_user", "user", "manage", "Manage users")
//
//	store, err := postgres.NewStore(postgres.Config{
//		DB:               db,
//		Catalog:          cat,
//		Tables:           map[rbac.ContentType]string{"project": "projects", "inventory": "inventories"},
//		TeamMembersTable: "team_members",
//	})
//	var authz rbac.Authorizer = store
//
// Callers depend on the Authorizer interface, never on the concrete store, so the
// decision (this package) and its enforcement (the consumer's handlers) stay
// separable — and this package pulls no database dependency. Every decision is
// deny-by-default and returns an error on infrastructure failure, so a database
// problem surfaces as a 500 rather than a silent allow.
//
// The engine assumes a fixed capability schema in the consumer's database
// (dab_permissions, role_definitions, role_definition_permissions, object_roles,
// role_user_assignments, role_team_assignments, role_evaluations, the membership
// table, and the rebuild_object_role_evaluations function); it owns the model but not
// the migrations, so the consumer provisions that schema and the two version together.
package rbac
