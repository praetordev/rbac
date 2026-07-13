package rbac

import _ "embed"

// Embedded policy fixtures used across the test suite. They live in a test file so the
// shipped package embeds no policy data of its own.

//go:embed policy.json
var policyJSON []byte

//go:embed policy-v1.json
var policyV1JSON []byte

//go:embed policy-v2.json
var policyV2JSON []byte
