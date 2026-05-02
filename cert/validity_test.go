package cert

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// makeCAAndServer builds an in-memory CA + a leaf server cert signed
// by it, then writes them into a fresh tmp dir in the standard
// {ca,server} layout. notAfter is the leaf's expiry. Returns the dir
// and the CA's SHA-256 fingerprint so tests can pin against it.
func makeCAAndServer(t *testing.T, notAfter time.Time) (dir, caFingerprint string) {
	t.Helper()

	caKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("ca keygen: %v", err)
	}
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test-root-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("create ca: %v", err)
	}
	caCert, _ := x509.ParseCertificate(caDER)

	srvKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("srv keygen: %v", err)
	}
	srvTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "module-service"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		DNSNames:     []string{"module-service"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	srvDER, err := x509.CreateCertificate(rand.Reader, srvTmpl, caCert, &srvKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("create srv: %v", err)
	}

	dir = t.TempDir()
	must := func(p string, b []byte, mode os.FileMode) {
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatalf("mkdir: %v", err)
		}
		if err := os.WriteFile(p, b, mode); err != nil {
			t.Fatalf("write %s: %v", p, err)
		}
	}
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})
	srvPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srvDER})
	keyDER, _ := x509.MarshalPKCS8PrivateKey(srvKey)
	srvKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})

	must(filepath.Join(dir, "ca", "ca.crt"), caPEM, 0o644)
	must(filepath.Join(dir, "server", "server.crt"), srvPEM, 0o644)
	must(filepath.Join(dir, "server", "server.key"), srvKeyPEM, 0o600)

	return dir, FingerprintSHA256(caCert)
}

func TestCheckLocalCert_OK(t *testing.T) {
	t.Parallel()

	dir, fp := makeCAAndServer(t, time.Now().Add(365*24*time.Hour))
	h := CheckLocalCert(dir, fp, 30*24*time.Hour)
	if !h.OK {
		t.Fatalf("expected OK, got reason=%q", h.Reason)
	}
}

func TestCheckLocalCert_MissingFiles(t *testing.T) {
	t.Parallel()

	h := CheckLocalCert(t.TempDir(), "abc", time.Hour)
	if h.OK {
		t.Fatal("expected failure on empty dir")
	}
}

func TestCheckLocalCert_FingerprintMismatch(t *testing.T) {
	t.Parallel()

	dir, _ := makeCAAndServer(t, time.Now().Add(time.Hour*24*365))
	// A wrong pin must reject even when the on-disk chain itself
	// is internally consistent.
	wrong := "0000000000000000000000000000000000000000000000000000000000000000"
	h := CheckLocalCert(dir, wrong, time.Hour)
	if h.OK {
		t.Fatal("expected fingerprint-mismatch failure")
	}
}

func TestCheckLocalCert_InsideRenewalWindow(t *testing.T) {
	t.Parallel()

	// Cert expires in 10 days; renewBefore is 30 days → must trigger
	// re-issue even though the cert is still technically valid.
	dir, fp := makeCAAndServer(t, time.Now().Add(10*24*time.Hour))
	h := CheckLocalCert(dir, fp, 30*24*time.Hour)
	if h.OK {
		t.Fatal("expected renewal-window failure")
	}
}

func TestCheckLocalCert_Expired(t *testing.T) {
	t.Parallel()

	dir, fp := makeCAAndServer(t, time.Now().Add(-time.Hour))
	h := CheckLocalCert(dir, fp, time.Hour)
	if h.OK {
		t.Fatal("expected expiry failure")
	}
}

func TestCheckLocalCert_FingerprintCheckSkippedWhenEmpty(t *testing.T) {
	t.Parallel()

	dir, _ := makeCAAndServer(t, time.Now().Add(365*24*time.Hour))
	// Empty pin disables the pin check (used in tests). Validity
	// itself is still required.
	h := CheckLocalCert(dir, "", 30*24*time.Hour)
	if !h.OK {
		t.Fatalf("expected OK with empty pin, got %q", h.Reason)
	}
}

func TestFingerprintSHA256_Stable(t *testing.T) {
	t.Parallel()

	_, fp := makeCAAndServer(t, time.Now().Add(365*24*time.Hour))
	if len(fp) != 64 {
		t.Fatalf("fingerprint length = %d, want 64 (32 bytes hex)", len(fp))
	}
	for _, c := range fp {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			t.Fatalf("fingerprint contains non-hex char %q in %s", c, fp)
		}
	}
}
