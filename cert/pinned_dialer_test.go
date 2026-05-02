package cert

import "testing"

func TestPinnedDial_RequiresFingerprint(t *testing.T) {
	t.Parallel()

	if _, err := PinnedDial("lcm:9101", ""); err == nil {
		t.Fatal("expected error for empty fingerprint")
	}
}

// The success path of PinnedDial requires a real TLS server to dial
// against — covered by the lcm-side integration tests rather than
// duplicating the cert-handshake plumbing here. The fingerprint
// matcher logic itself (which is the security-critical bit) is
// covered by TestFingerprintSHA256_Stable in validity_test.go and
// the per-cert hash is computed identically in PinnedDial's
// VerifyPeerCertificate callback.
