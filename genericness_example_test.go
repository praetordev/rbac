package rbac

import "fmt"

// Example_genericnessBoundary demonstrates a hard edge of the closed vocabulary: the engine's
// only comparison is string equality, so "*" is not a wildcard. Under a policy that grants by
// EXACT capability match, a grant whose capability is "*" does not grant "dock" — because the
// string "*" is not the string "dock". A wildcard only works where a policy explicitly opts
// in with eq(grant.cap, "*").
func Example_genericnessBoundary() {
	exact := []byte(`[
		{"name":"allow-exact","effect":"allow","when":{"all":[
			{"eq":[{"attr":"grant.effect"},{"lit":"allow"}]},
			{"eq":[{"attr":"grant.cap"},{"attr":"need"}]},
			{"eq":[{"attr":"grant.scope"},{"attr":"scope"}]}
		]}}
	]`)
	snap, err := NewSnapshot("exact-v1", exact, DenyOverrides)
	if err != nil {
		panic(err)
	}

	star := []Grant{{Capability: "*", Scope: "ship-9", Effect: Allow}}
	d := Decide(snap, Query{Grants: star, Need: "dock", Scope: "ship-9"})
	fmt.Printf("grant \"*\" vs need \"dock\" under exact-match policy -> allow=%v\n", d.Allow)
	fmt.Println(`("*" is a literal string here, not a wildcard)`)

	// Output:
	// grant "*" vs need "dock" under exact-match policy -> allow=false
	// ("*" is a literal string here, not a wildcard)
}
