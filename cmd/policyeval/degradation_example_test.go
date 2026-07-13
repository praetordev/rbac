package main

import "fmt"

// Example_absentVsEmpty shows that an ABSENT attribute is a non-match against every value —
// including the empty string — and is therefore distinct in the VERDICT from an attribute
// that is present and holds "".
func Example_absentVsEmpty() {
	grant := []Grant{{Capability: "x", Scope: "", Effect: Allow}}

	// "region" is not one of the five attributes the engine exposes -> ABSENT. Comparing an
	// absent attribute even to "" does not match (three-valued logic: absent -> unknown).
	absentPolicy := []byte(`[{"name":"r","effect":"allow","when":{"eq":[{"attr":"region"},{"lit":""}]}}]`)
	aSnap, err := NewSnapshot("absent", absentPolicy, denyOverrides)
	if err != nil {
		panic(err)
	}
	a := Decide(aSnap, Query{Grants: grant, Need: "x", Scope: ""})

	// "scope" IS exposed; here it is present and holds "" (a global check) -> PRESENT-EMPTY,
	// which does match "".
	emptyPolicy := []byte(`[{"name":"r","effect":"allow","when":{"eq":[{"attr":"scope"},{"lit":""}]}}]`)
	eSnap, err := NewSnapshot("empty", emptyPolicy, denyOverrides)
	if err != nil {
		panic(err)
	}
	e := Decide(eSnap, Query{Grants: grant, Need: "x", Scope: ""})

	fmt.Printf("absent 'region' == \"\"  -> allow=%v (absent never matches, even vs \"\")\n", a.Allow)
	fmt.Printf("present 'scope'  == \"\"  -> allow=%v (present-empty matches \"\")\n", e.Allow)
	// Output:
	// absent 'region' == ""  -> allow=false (absent never matches, even vs "")
	// present 'scope'  == ""  -> allow=true (present-empty matches "")
}

// Example_failClosed shows the two fail-closed paths: no snapshot denies, and a rejected bad
// load leaves the last known-good snapshot serving.
func Example_failClosed() {
	req := Query{Grants: []Grant{{Capability: "dock", Scope: "ship-9", Effect: Allow}}, Need: "dock", Scope: "ship-9"}

	// 1) No snapshot installed: deny, never open, never panic.
	empty := NewHolder(nil)
	fmt.Println("no snapshot        -> allow:", empty.Decide(req).Allow)

	// 2) A bad bundle is rejected; the last known-good snapshot stays installed.
	good, err := NewSnapshot("good", []byte(fleetPolicy), denyOverrides)
	if err != nil {
		panic(err)
	}
	h := NewHolder(good)
	loadErr := h.Load("bad", []byte(`[{"name":"r","effect":"nope","when":{"lit":"x"}}]`), denyOverrides)
	fmt.Println("bad load rejected  ->", loadErr != nil)
	fmt.Println("still serving good -> allow:", h.Decide(req).Allow)
	// Output:
	// no snapshot        -> allow: false
	// bad load rejected  -> true
	// still serving good -> allow: true
}

// Example_disclosure shows the two disclosure audiences. An explicit deny and a default-deny
// are INDISTINGUISHABLE to the caller under Minimal (both "access denied"), while Full — for
// your own logs — records how each was reached and so differs.
func Example_disclosure() {
	snap, err := NewSnapshot("fleet-v1", []byte(fleetPolicy), denyOverrides)
	if err != nil {
		panic(err)
	}

	// Explicit deny (the quarantine veto) vs default-deny (no rule matched).
	explicit := Decide(snap, Query{Grants: []Grant{{Capability: "dock", Scope: "ship-13", Effect: Allow}}, Need: "dock", Scope: "ship-13"})
	byDefault := Decide(snap, Query{Grants: []Grant{{Capability: "launch", Scope: "ship-9", Effect: Allow}}, Need: "launch", Scope: "ship-9"})

	fmt.Println("to the caller (Minimal):")
	fmt.Printf("  explicit deny -> %q\n", explicit.Disclose(Minimal))
	fmt.Printf("  default deny  -> %q\n", byDefault.Disclose(Minimal))
	fmt.Println("indistinguishable to the caller:", explicit.Disclose(Minimal) == byDefault.Disclose(Minimal))
	fmt.Println("but Full (your logs) differs:", explicit.Disclose(Full) != byDefault.Disclose(Full))
	// Output:
	// to the caller (Minimal):
	//   explicit deny -> "access denied"
	//   default deny  -> "access denied"
	// indistinguishable to the caller: true
	// but Full (your logs) differs: true
}
