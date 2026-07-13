package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sync"
	"testing"
)

// Story 4 (policy source integrity): a tampered or untrusted bundle must be rejected before
// it can become the current snapshot, rejection must fall back to last known-good (never
// open), and the swap must stay atomic under concurrency.
//
// The verifier below is a CONSUMER-SIDE reference (authenticated integrity via HMAC-SHA256).
// The engine ships no crypto; it only guarantees verify-before-swap and fail-closed.

// signBundle produces a signed bundle: <policy> 0x00 <hex hmac-sha256(policy)>. JSON policy
// never contains a NUL byte, so the first NUL cleanly separates payload from signature.
func signBundle(secret, policy []byte) []byte {
	mac := hmac.New(sha256.New, secret)
	mac.Write(policy)
	sig := []byte(hex.EncodeToString(mac.Sum(nil)))
	b := make([]byte, 0, len(policy)+1+len(sig))
	b = append(b, policy...)
	b = append(b, 0)
	return append(b, sig...)
}

// hmacVerifier is a Verifier that accepts only bundles signed with secret.
func hmacVerifier(secret []byte) Verifier {
	return func(bundle []byte) ([]byte, error) {
		i := bytes.IndexByte(bundle, 0)
		if i < 0 {
			return nil, fmt.Errorf("bundle has no signature")
		}
		payload, sig := bundle[:i], bundle[i+1:]
		mac := hmac.New(sha256.New, secret)
		mac.Write(payload)
		want := []byte(hex.EncodeToString(mac.Sum(nil)))
		if !hmac.Equal(sig, want) {
			return nil, fmt.Errorf("signature mismatch")
		}
		return payload, nil
	}
}

var integritySecret = []byte("trusted-signing-key")

func writeReqAt(scope string) Query {
	return Query{Grants: []Grant{{"write", scope, Allow}}, Need: "write", Scope: scope}
}

// A properly signed bundle installs and takes effect.
func TestVerifiedBundleInstalls(t *testing.T) {
	verify := hmacVerifier(integritySecret)
	h := NewHolder(mustSnap(t, "v1", policyV1JSON, denyOverrides)) // v1 denies write

	if h.Decide(writeReqAt("obj1")).Allow {
		t.Fatal("v1 should DENY write (setup)")
	}
	if err := h.LoadBundle("v2", signBundle(integritySecret, policyV2JSON), verify, denyOverrides); err != nil {
		t.Fatalf("verified bundle must install: %v", err)
	}
	if got := h.Decide(writeReqAt("obj1")); !got.Allow || got.Snapshot != "v2" {
		t.Errorf("after verified load want ALLOW under v2, got allow=%v snapshot=%q", got.Allow, got.Snapshot)
	}
}

// A tampered bundle is rejected before it can become the snapshot; the last known-good stays
// installed and keeps denying what it denied — access never opens.
func TestTamperedBundleRejectedKeepsLastKnownGood(t *testing.T) {
	verify := hmacVerifier(integritySecret)
	readReq := Query{Grants: []Grant{{"read", "obj1", Allow}}, Need: "read", Scope: "obj1"}
	h := NewHolder(mustSnap(t, "v1", policyV1JSON, denyOverrides))

	good := signBundle(integritySecret, policyV2JSON)
	tampered := append([]byte(nil), good...)
	tampered[0] ^= 0xff // flip a payload byte -> HMAC no longer matches

	if err := h.LoadBundle("v2", tampered, verify, denyOverrides); err == nil {
		t.Fatal("tampered bundle must be rejected")
	}
	if h.Current().ID() != "v1" {
		t.Fatalf("rejected load must keep last known-good v1, got %q", h.Current().ID())
	}
	if h.Decide(writeReqAt("obj1")).Allow {
		t.Error("v1 must still DENY write after a rejected load (no accidental open)")
	}
	if !h.Decide(readReq).Allow {
		t.Error("v1 must still ALLOW read after a rejected load")
	}
}

// A bundle signed by an untrusted key (wrong secret) is rejected.
func TestUntrustedBundleRejected(t *testing.T) {
	verify := hmacVerifier(integritySecret)
	h := NewHolder(mustSnap(t, "v1", policyV1JSON, denyOverrides))

	forged := signBundle([]byte("attacker-key"), policyV2JSON)
	if err := h.LoadBundle("v2", forged, verify, denyOverrides); err == nil {
		t.Fatal("bundle signed with an untrusted key must be rejected")
	}
	if h.Current().ID() != "v1" || h.Decide(writeReqAt("obj1")).Allow {
		t.Error("untrusted load must not disturb v1 or open access")
	}
}

// Loading without a verifier is refused outright (fail closed) — no bypass by omission.
func TestNilVerifierRefused(t *testing.T) {
	h := NewHolder(mustSnap(t, "v1", policyV1JSON, denyOverrides))
	if err := h.LoadBundle("v2", policyV2JSON, nil, denyOverrides); err == nil {
		t.Fatal("loading a bundle with no verifier must be refused")
	}
	if h.Current().ID() != "v1" {
		t.Error("refused load must not disturb the current snapshot")
	}
}

// A verified but malformed/pathological bundle still fails at parse (the parser bounds apply
// after verification) and falls back to last known-good.
func TestVerifiedButMalformedRejected(t *testing.T) {
	verify := hmacVerifier(integritySecret)
	h := NewHolder(mustSnap(t, "v1", policyV1JSON, denyOverrides))

	// Authentically signed, but the payload is a depth-bomb the parser rejects.
	bundle := signBundle(integritySecret, nestedAllPolicy(2000))
	if err := h.LoadBundle("bad", bundle, verify, denyOverrides); err == nil {
		t.Fatal("a verified-but-malformed bundle must still be rejected at parse")
	}
	if h.Current().ID() != "v1" {
		t.Error("parse failure after verification must keep last known-good")
	}
}

// Under concurrency, every decision reflects a whole, valid snapshot (v1 denies write, v2
// allows it) — never a partial or tampered state — and a tampered load never becomes current.
func TestConcurrentLoadBundleAtomicity(t *testing.T) {
	verify := hmacVerifier(integritySecret)
	good := signBundle(integritySecret, policyV2JSON)
	tampered := append([]byte(nil), good...)
	tampered[0] ^= 0xff

	h := NewHolder(mustSnap(t, "v1", policyV1JSON, denyOverrides))
	req := writeReqAt("obj1")

	var wg sync.WaitGroup
	for i := 0; i < 8; i++ { // readers
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 2000; j++ {
				d := h.Decide(req)
				switch d.Snapshot {
				case "v1":
					if d.Allow {
						t.Errorf("v1 must DENY write")
					}
				case "v2":
					if !d.Allow {
						t.Errorf("v2 must ALLOW write")
					}
				default:
					t.Errorf("decision observed an unknown/partial snapshot %q", d.Snapshot)
				}
			}
		}()
	}
	for i := 0; i < 4; i++ { // writers: interleave verified and tampered loads
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 500; j++ {
				h.LoadBundle("v2", good, verify, denyOverrides)     // may install v2
				h.LoadBundle("v2", tampered, verify, denyOverrides) // must be rejected, no swap
			}
		}()
	}
	wg.Wait()

	if id := h.Current().ID(); id != "v1" && id != "v2" {
		t.Fatalf("current snapshot is neither known-good value: %q", id)
	}
}
