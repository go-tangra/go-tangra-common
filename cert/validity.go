package cert

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"os"
	"strings"
	"time"
)

// CertHealth is the result of CheckLocalCert. Passing means the
// caller can use the cert as-is; the named failure reasons let the
// caller log why it's about to re-issue.
type CertHealth struct {
	OK     bool
	Reason string // human-readable; empty when OK
	Cert   *x509.Certificate
	CA     *x509.Certificate
}

// CheckLocalCert validates that ${certsDir}/{ca,server} contain a
// usable mTLS server cert + CA. Returns OK only when ALL of:
//
//   - both files exist and parse as PEM-encoded x509
//   - the server cert was signed by the CA
//   - NotBefore <= now < (NotAfter - renewBefore)
//   - the CA's SHA-256 fingerprint matches expectedFingerprint when
//     expectedFingerprint is non-empty (an empty fingerprint disables
//     the pin check — used in tests; production callers always pin)
//
// Any failure is non-fatal at this layer: it just means the caller
// should ask LCM for fresh certs. Reason is suitable for log output.
func CheckLocalCert(certsDir, expectedFingerprint string, renewBefore time.Duration) CertHealth {
	caPath := certsDir + "/ca/ca.crt"
	srvPath := certsDir + "/server/server.crt"
	keyPath := certsDir + "/server/server.key"

	for _, p := range []string{caPath, srvPath, keyPath} {
		if _, err := os.Stat(p); err != nil {
			return CertHealth{Reason: fmt.Sprintf("missing %s: %v", p, err)}
		}
	}

	caBytes, err := os.ReadFile(caPath)
	if err != nil {
		return CertHealth{Reason: fmt.Sprintf("read ca: %v", err)}
	}
	ca, err := parseCert(caBytes)
	if err != nil {
		return CertHealth{Reason: fmt.Sprintf("parse ca: %v", err)}
	}

	if expectedFingerprint != "" {
		gotFp := FingerprintSHA256(ca)
		if !strings.EqualFold(gotFp, expectedFingerprint) {
			// Fingerprint mismatch is the loudest failure mode — it
			// means the on-disk CA is from a different LCM than the
			// operator pinned. Re-issuing here would happily accept
			// whatever the dialer is told to trust; we let Ensure()
			// re-bootstrap from the pinned LCM so the CA on disk
			// gets replaced with the right one.
			return CertHealth{
				Reason: fmt.Sprintf("CA fingerprint mismatch: disk=%s pinned=%s", gotFp, expectedFingerprint),
				CA:     ca,
			}
		}
	}

	srvBytes, err := os.ReadFile(srvPath)
	if err != nil {
		return CertHealth{Reason: fmt.Sprintf("read server cert: %v", err), CA: ca}
	}
	srv, err := parseCert(srvBytes)
	if err != nil {
		return CertHealth{Reason: fmt.Sprintf("parse server cert: %v", err), CA: ca}
	}

	pool := x509.NewCertPool()
	pool.AddCert(ca)
	if _, err := srv.Verify(x509.VerifyOptions{
		Roots:     pool,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}); err != nil {
		return CertHealth{Reason: fmt.Sprintf("verify chain: %v", err), Cert: srv, CA: ca}
	}

	now := time.Now()
	if now.Before(srv.NotBefore) {
		return CertHealth{Reason: fmt.Sprintf("not yet valid (notBefore=%s)", srv.NotBefore), Cert: srv, CA: ca}
	}
	cutoff := srv.NotAfter.Add(-renewBefore)
	if !now.Before(cutoff) {
		return CertHealth{
			Reason: fmt.Sprintf("inside renewal window: notAfter=%s, renewBefore=%s", srv.NotAfter, renewBefore),
			Cert:   srv, CA: ca,
		}
	}

	return CertHealth{OK: true, Cert: srv, CA: ca}
}

// FingerprintSHA256 returns the lowercase-hex SHA-256 of a cert's
// DER bytes. Used as the wire form of the CA pin everywhere.
func FingerprintSHA256(c *x509.Certificate) string {
	sum := sha256.Sum256(c.Raw)
	return hex.EncodeToString(sum[:])
}

// FingerprintSHA256PEM is the same calculation done from a PEM string
// — convenient for verifying a fingerprint provided in env vars.
func FingerprintSHA256PEM(pemBytes []byte) (string, error) {
	c, err := parseCert(pemBytes)
	if err != nil {
		return "", err
	}
	return FingerprintSHA256(c), nil
}

func parseCert(pemBytes []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, fmt.Errorf("no PEM block found")
	}
	if block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("expected CERTIFICATE block, got %q", block.Type)
	}
	return x509.ParseCertificate(block.Bytes)
}
