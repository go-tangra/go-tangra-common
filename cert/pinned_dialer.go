package cert

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"strings"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

// PinnedDial returns a gRPC client connection to addr whose TLS
// handshake will only succeed if the server's leaf or chain matches
// the supplied SHA-256 fingerprint. The pin is verified inside
// VerifyPeerCertificate, which runs after the chain is presented but
// before the handshake completes — so a mismatch turns into a normal
// gRPC dial error, no half-open connection.
//
// expectedFingerprint MUST be non-empty. An empty pin is a config
// error and returns immediately. (TOFU is deliberately not supported
// here — the operator pins on day one.)
//
// The caller is expected to use this for the bootstrap connection to
// LCM only. After bootstrap, modules dial peers via the standard
// mTLS path with their own client cert.
func PinnedDial(addr, expectedFingerprint string, extra ...grpc.DialOption) (*grpc.ClientConn, error) {
	if expectedFingerprint == "" {
		return nil, fmt.Errorf("PinnedDial: expectedFingerprint is required (set LCM_CA_FINGERPRINT)")
	}
	wantFP := strings.ToLower(strings.TrimSpace(expectedFingerprint))

	tlsCfg := &tls.Config{
		// We do our own verification below. ServerName is still set
		// so SNI works — some load balancers route on it.
		InsecureSkipVerify: true, //nolint:gosec // overridden by VerifyPeerCertificate
		MinVersion:         tls.VersionTLS12,
		VerifyPeerCertificate: func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			// rawCerts is the chain the server sent, leaf first.
			// We accept the connection iff at least one cert in the
			// chain matches the pin — typically the root CA, but
			// matching the leaf or an intermediate is fine too. This
			// makes rotation possible: ship a new server cert signed
			// by the same pinned CA and clients keep working without
			// touching their pin.
			if len(rawCerts) == 0 {
				return fmt.Errorf("server presented no certificates")
			}
			for _, der := range rawCerts {
				c, err := x509.ParseCertificate(der)
				if err != nil {
					continue
				}
				if FingerprintSHA256(c) == wantFP {
					return nil
				}
			}
			return fmt.Errorf("server cert chain does not match pinned fingerprint %s", wantFP)
		},
	}

	opts := append([]grpc.DialOption{
		grpc.WithTransportCredentials(credentials.NewTLS(tlsCfg)),
	}, extra...)

	conn, err := grpc.NewClient(addr, opts...)
	if err != nil {
		return nil, fmt.Errorf("dial %s: %w", addr, err)
	}
	return conn, nil
}
