package rbac

import "fmt"

// ---- Policy source integrity (the load-path trust seam) ------------------------
//
// Policy is pulled live and swapped into snapshots. A malicious snapshot is the strongest
// attack on the engine, so a bundle's provenance must be established BEFORE it can become the
// current snapshot. The engine performs no cryptography itself — signing/verification is
// consumed, not built here (see the trust boundary, row 11). It provides only the seam and
// the ordering guarantee: a bundle is verified first, parsed second, and swapped last, and
// any failure leaves the last known-good snapshot untouched.

// Verifier establishes the trust of a policy bundle. It receives the raw bundle and returns
// the trusted policy bytes to parse, or an error if the bundle is untrusted or tampered. The
// consumer supplies the real check (a signature over a trusted channel); the engine only
// enforces that it runs before a swap and that a failed check never opens access.
type Verifier func(bundle []byte) (policy []byte, err error)

// PassthroughVerifier is the loader's DEFAULT, DEFERRED integrity step: it accepts every
// bundle unchanged. It is a NO-OP placeholder, NOT a real authenticity check.
//
// Real integrity depends on the policy source — you sign a git repo differently than an HTTP
// endpoint than a local file — so implementing it now would be guessing (see the epic
// non-goals and TRUST-BOUNDARY.md row 11). This is the ONE obvious, documented place a real
// check drops in: pass a real Verifier to the loader (NewLoader(..., WithVerifier(real))) and
// nothing else changes. Until then, the loader's integrity step is present and wired to fail
// closed — it simply passes everything.
func PassthroughVerifier(bundle []byte) ([]byte, error) { return bundle, nil }

// LoadBundle verifies bundle with v and installs it ONLY if verification AND parsing both
// succeed. Ordering is the guarantee:
//  1. Verify integrity/authenticity first — unverified bytes are never parsed or installed.
//  2. Parse under the parser bounds (Story 1) — a verified-but-malformed bundle still fails.
//  3. Swap atomically (the single pointer store in Set) — no in-flight decision observes a
//     partial or malicious update.
//
// Any failure (nil verifier, failed verification, or failed parse) returns an error and
// leaves the current, last known-good snapshot in place. A bad bundle can never become the
// current snapshot, clear the policy, or open access.
func (h *Holder) LoadBundle(id string, bundle []byte, v Verifier, combine Strategy) error {
	if v == nil {
		// No trust anchor => refuse. Loading an unverified bundle by omission must be
		// impossible, not silently permitted.
		return fmt.Errorf("bundle %q: no verifier supplied (refusing to load; fail closed)", id)
	}
	policy, err := v(bundle)
	if err != nil {
		return fmt.Errorf("bundle %q failed integrity verification: %w", id, err)
	}
	// Load parses under bounds and swaps atomically, itself failing closed on a parse error.
	return h.Load(id, policy, combine)
}
