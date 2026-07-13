package main

import "fmt"

// Example_flattening shows that hierarchy is the consumer's responsibility. The engine
// compares scope strings by exact equality and has no prefix or containment logic, so a
// hierarchy (fleet -> squadron -> ship) must be flattened into namespaced scopes before the
// call. Here the subject's command over squadron-1 is flattened into one grant per contained
// ship.
func Example_flattening() {
	policy := []byte(`[
		{"name":"allow","effect":"allow","when":{"all":[
			{"eq":[{"attr":"grant.effect"},{"lit":"allow"}]},
			{"eq":[{"attr":"grant.cap"},{"attr":"need"}]},
			{"eq":[{"attr":"grant.scope"},{"attr":"scope"}]}
		]}}
	]`)
	snap, err := NewSnapshot("fleet-v1", policy, denyOverrides)
	if err != nil {
		panic(err)
	}

	// Flatten "commands squadron-1" into one grant per contained ship (namespaced scopes).
	commands := []string{"squadron-1/ship-9", "squadron-1/ship-10"}
	grants := make([]Grant, len(commands))
	for i, s := range commands {
		grants[i] = Grant{Capability: "dock", Scope: s, Effect: Allow}
	}

	// A fully-qualified request matches a flattened grant.
	in := Decide(snap, Query{Grants: grants, Need: "dock", Scope: "squadron-1/ship-9"})
	fmt.Println("dock squadron-1/ship-9      ->", in.Allow)

	// A ship outside the flattened set is denied.
	out := Decide(snap, Query{Grants: grants, Need: "dock", Scope: "squadron-2/ship-1"})
	fmt.Println("dock squadron-2/ship-1      ->", out.Allow)

	// A grant at the un-flattened PARENT does not cover a child — the engine has no prefix
	// logic, so this is the mistake flattening avoids.
	parent := []Grant{{Capability: "dock", Scope: "squadron-1", Effect: Allow}}
	naive := Decide(snap, Query{Grants: parent, Need: "dock", Scope: "squadron-1/ship-9"})
	fmt.Println("grant 'squadron-1' vs child ->", naive.Allow)

	// Output:
	// dock squadron-1/ship-9      -> true
	// dock squadron-2/ship-1      -> false
	// grant 'squadron-1' vs child -> false
}
