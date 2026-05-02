package cert

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"net"
	"strings"
)

const (
	// keySizeBits chooses RSA-2048: small enough that a per-boot
	// keygen is sub-second on container CPUs, large enough to remain
	// safe through the 1-year cert lifetime. Bumping to 4096 would
	// quadruple keygen cost for no real-world security gain.
	keySizeBits = 2048
)

// GenerateKeyAndCSR creates a fresh RSA-2048 keypair and a
// PEM-encoded PKCS#10 CSR carrying the requested CN + SANs. The
// private key never leaves this process — Ensure() persists it to
// disk after LCM signs the CSR.
//
// dnsNames and ipAddresses are SANs on the resulting certificate.
// Both are passed through verbatim; the caller is responsible for
// computing the right set for its module (typically:
// {moduleID + "-service"} for DNS, plus locally-bound interface IPs).
func GenerateKeyAndCSR(commonName string, dnsNames []string, ipAddresses []string) (*rsa.PrivateKey, []byte, error) {
	if commonName == "" {
		return nil, nil, fmt.Errorf("commonName is required")
	}

	key, err := rsa.GenerateKey(rand.Reader, keySizeBits)
	if err != nil {
		return nil, nil, fmt.Errorf("rsa keygen: %w", err)
	}

	// Filter and parse IPs once so the CSR carries net.IP values, not
	// strings. Bad strings are silently dropped — the cert still gets
	// signed with whatever valid SANs remain, and the operator notices
	// at runtime when their unreachable IP doesn't validate.
	parsedIPs := make([]net.IP, 0, len(ipAddresses))
	for _, raw := range ipAddresses {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		if ip := net.ParseIP(raw); ip != nil {
			parsedIPs = append(parsedIPs, ip)
		}
	}

	tmpl := &x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName:   commonName,
			Organization: []string{"tangra"},
		},
		DNSNames:    dnsNames,
		IPAddresses: parsedIPs,
	}

	csrDER, err := x509.CreateCertificateRequest(rand.Reader, tmpl, key)
	if err != nil {
		return nil, nil, fmt.Errorf("create csr: %w", err)
	}
	csrPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE REQUEST",
		Bytes: csrDER,
	})
	return key, csrPEM, nil
}

// MarshalKeyPEM encodes an RSA private key as PKCS#8 PEM. Used by
// Ensure() right before writing to disk. PKCS#8 is the modern format
// — interoperable with everything we run, no -----BEGIN RSA PRIVATE
// KEY----- legacy headers.
func MarshalKeyPEM(key *rsa.PrivateKey) ([]byte, error) {
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("marshal pkcs8: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: der,
	}), nil
}
