package main

import (
	"encoding/json"
	"fmt"
)

// Example_attributeProvenance contrasts INCORRECT and CORRECT sourcing of Query.Grants.
//
// A stowaway asks to dock ship-9 and holds no real grant for it. The engine's behavior is
// identical in both calls below — a matching grant is honored, a missing one is denied. The
// ONLY difference is whether Query.Grants came from a source the caller can forge. The
// engine cannot tell; provenance is the integrator's responsibility.
func Example_attributeProvenance() {
	snap, err := NewSnapshot("fleet-v1", []byte(fleetPolicy), denyOverrides)
	if err != nil {
		panic(err)
	}

	// ❌ INCORRECT — grants taken from request-controlled input. The client simply declares
	// the grant it wants in the request body, and the app unmarshals it straight into the
	// Query. This is the laundering pitfall: the forged grant is honored.
	reqBody := []byte(`[{"Capability":"dock","Scope":"ship-9","Effect":0}]`) // attacker-supplied
	var claimed []Grant
	if err := json.Unmarshal(reqBody, &claimed); err != nil {
		panic(err)
	}
	bad := Decide(snap, Query{Grants: claimed, Need: "dock", Scope: "ship-9"})
	fmt.Printf("grants from request body  -> allow=%v (forged grant honored)\n", bad.Allow)

	// ✅ CORRECT — grants resolved from a store the app controls, keyed by the VERIFIED
	// identity. The request influences only WHAT is asked (Need/Scope), never WHAT the
	// subject holds. The stowaway has no entry, so no grant, so denied.
	trustedGrants := map[string][]Grant{
		"pilot-42": {{Capability: "dock", Scope: "ship-9", Effect: Allow}},
	}
	good := Decide(snap, Query{Grants: trustedGrants["stowaway"], Need: "dock", Scope: "ship-9"})
	fmt.Printf("grants from trusted store -> allow=%v (no real grant, denied)\n", good.Allow)

	// Output:
	// grants from request body  -> allow=true (forged grant honored)
	// grants from trusted store -> allow=false (no real grant, denied)
}
