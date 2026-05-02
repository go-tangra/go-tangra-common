package cert

import (
	"crypto/x509"
	"encoding/pem"
	"net"
	"strings"
	"testing"
)

func TestGenerateKeyAndCSR(t *testing.T) {
	t.Parallel()

	key, csrPEM, err := GenerateKeyAndCSR(
		"sms-gw-service",
		[]string{"sms-gw-service", "sms-gw-service.tangra.local"},
		[]string{"10.0.0.1", "::1", "not-an-ip", "  192.168.0.1  ", ""},
	)
	if err != nil {
		t.Fatalf("GenerateKeyAndCSR: %v", err)
	}
	if key == nil || key.PublicKey.N.BitLen() < 2000 {
		t.Fatalf("key bit length too small: %d", key.PublicKey.N.BitLen())
	}

	block, _ := pem.Decode(csrPEM)
	if block == nil || block.Type != "CERTIFICATE REQUEST" {
		t.Fatalf("CSR PEM block has wrong shape: %+v", block)
	}

	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		t.Fatalf("parse csr: %v", err)
	}
	if err := csr.CheckSignature(); err != nil {
		t.Fatalf("csr signature invalid: %v", err)
	}

	if csr.Subject.CommonName != "sms-gw-service" {
		t.Errorf("CN = %q", csr.Subject.CommonName)
	}
	if got, want := csr.DNSNames, []string{"sms-gw-service", "sms-gw-service.tangra.local"}; !equalStrings(got, want) {
		t.Errorf("DNSNames = %v, want %v", got, want)
	}

	// IPs: invalid + empty entries dropped, whitespace trimmed,
	// surviving v4 + v6 retained.
	wantIPs := map[string]bool{"10.0.0.1": true, "::1": true, "192.168.0.1": true}
	if len(csr.IPAddresses) != len(wantIPs) {
		t.Fatalf("IPAddresses = %v, want %v", csr.IPAddresses, wantIPs)
	}
	for _, ip := range csr.IPAddresses {
		if !wantIPs[ip.String()] {
			t.Errorf("unexpected IP in CSR: %s", ip)
		}
	}
}

func TestGenerateKeyAndCSR_RequiresCN(t *testing.T) {
	t.Parallel()

	_, _, err := GenerateKeyAndCSR("", nil, nil)
	if err == nil {
		t.Fatal("expected error for empty CommonName, got nil")
	}
}

func TestMarshalKeyPEM_RoundTrip(t *testing.T) {
	t.Parallel()

	key, _, err := GenerateKeyAndCSR("anyone", nil, nil)
	if err != nil {
		t.Fatalf("GenerateKeyAndCSR: %v", err)
	}
	pemBytes, err := MarshalKeyPEM(key)
	if err != nil {
		t.Fatalf("MarshalKeyPEM: %v", err)
	}
	if !strings.Contains(string(pemBytes), "-----BEGIN PRIVATE KEY-----") {
		t.Fatalf("expected PKCS#8 PRIVATE KEY block, got: %s", pemBytes)
	}
	block, _ := pem.Decode(pemBytes)
	if block == nil || block.Type != "PRIVATE KEY" {
		t.Fatalf("PEM block has wrong shape: %+v", block)
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		t.Fatalf("ParsePKCS8PrivateKey: %v", err)
	}
	if parsed == nil {
		t.Fatal("ParsePKCS8PrivateKey returned nil")
	}
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// Compile-time check that net.IP imports stay used even if the test
// trims down — keeps the import block honest.
var _ = net.ParseIP
