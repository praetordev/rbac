package rbac

// Catalog is a consumer-defined vocabulary: which actions are valid on which content
// types, plus any global-scope-only (system) capabilities. The engine validates every
// authorization question against a Catalog and has no built-in content types of its
// own — construct one with NewCatalog and declare the vocabulary with Type and System.
//
// A Catalog is built once at startup and then read-only; the builder methods are not
// safe for concurrent use, but IsValid and the accessors are.
type Catalog struct {
	order   []ContentType                   // content types, in declared order
	actions map[ContentType][]Action        // valid actions per type, in declared order
	valid   map[ContentType]map[Action]bool // membership index
	sysList []DABPermission                 // global-only capabilities, in declared order
	sysSet  map[string]bool                 // system codename membership
}

// NewCatalog returns an empty catalog. Declare content-type capabilities with Type and
// global-only capabilities with System; both are chainable.
func NewCatalog() *Catalog {
	return &Catalog{
		actions: map[ContentType][]Action{},
		valid:   map[ContentType]map[Action]bool{},
		sysSet:  map[string]bool{},
	}
}

// Type declares that ct supports the given actions, preserving declared order. It may
// be called more than once for the same content type; duplicate actions are ignored.
func (c *Catalog) Type(ct ContentType, actions ...Action) *Catalog {
	if c.valid[ct] == nil {
		c.valid[ct] = map[Action]bool{}
		c.order = append(c.order, ct)
	}
	for _, a := range actions {
		if !c.valid[ct][a] {
			c.valid[ct][a] = true
			c.actions[ct] = append(c.actions[ct], a)
		}
	}
	return c
}

// System declares a global-scope-only capability identified by codename (e.g.
// "manage_user"). content, action and label are descriptive metadata for the seeded
// dab_permissions row. A system capability is meaningful only at global scope, so a
// role that confers it at object/team scope is a privilege-escalation bug the consumer
// should reject (see SystemCapabilitiesIn). Duplicate codenames are ignored.
func (c *Catalog) System(codename, content, action, label string) *Catalog {
	if !c.sysSet[codename] {
		c.sysSet[codename] = true
		name := label
		c.sysList = append(c.sysList, DABPermission{
			Codename:    codename,
			ContentType: content,
			Action:      action,
			Name:        &name,
		})
	}
	return c
}

// IsValid reports whether (ct, action) is a declared content-type capability.
func (c *Catalog) IsValid(ct ContentType, a Action) bool {
	return c.valid[ct][a]
}

// ContentTypes returns the declared content types, in order.
func (c *Catalog) ContentTypes() []ContentType {
	out := make([]ContentType, len(c.order))
	copy(out, c.order)
	return out
}

// Permissions returns the content-type capabilities to seed into dab_permissions, in
// declared order. IDs/CreatedAt are unset (assigned by the database).
func (c *Catalog) Permissions() []DABPermission {
	var out []DABPermission
	for _, ct := range c.order {
		for _, a := range c.actions[ct] {
			name := defaultLabel(a, ct)
			out = append(out, DABPermission{
				Codename:    Codename(ct, a),
				ContentType: string(ct),
				Action:      string(a),
				Name:        &name,
			})
		}
	}
	return out
}

// SystemPermissions returns the global-only capabilities to seed into dab_permissions,
// in declared order.
func (c *Catalog) SystemPermissions() []DABPermission {
	out := make([]DABPermission, len(c.sysList))
	copy(out, c.sysList)
	return out
}

// IsSystemCapability reports whether codename is a declared global-only capability.
func (c *Catalog) IsSystemCapability(codename string) bool {
	return c.sysSet[codename]
}

// SystemCapabilitiesIn returns the system capabilities present in codenames — the ones
// a non-global (object/team-scoped) role must not confer. A caller validating a custom
// scoped RoleDefinition should reject it when this is non-empty. Order follows the
// input; the result is nil when there are none.
func (c *Catalog) SystemCapabilitiesIn(codenames []string) []string {
	var out []string
	for _, cn := range codenames {
		if c.sysSet[cn] {
			out = append(out, cn)
		}
	}
	return out
}
