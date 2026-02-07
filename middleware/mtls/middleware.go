package mtls

import (
	"context"
	"crypto/x509"
	"fmt"
	"slices"
	"time"

	"github.com/go-kratos/kratos/v2/errors"
	"github.com/go-kratos/kratos/v2/log"
	"github.com/go-kratos/kratos/v2/middleware"
	"github.com/go-kratos/kratos/v2/transport"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
)

// Options configures the mTLS middleware
type Options struct {
	// PublicEndpoints are endpoints that don't require mTLS authentication
	PublicEndpoints []string

	// TrustedOrgs are organization values that are considered trusted issuers
	// If empty, defaults to ["LCM Certificate Authority", "LCM"]
	TrustedOrgs []string

	// TrustedOrgUnits are organizational unit values that are considered trusted
	TrustedOrgUnits []string
}

// Option is a function that configures Options
type Option func(*Options)

// WithPublicEndpoints sets the public endpoints that don't require mTLS
func WithPublicEndpoints(endpoints ...string) Option {
	return func(o *Options) {
		o.PublicEndpoints = append(o.PublicEndpoints, endpoints...)
	}
}

// WithTrustedOrgs sets the trusted organization values for certificate validation
func WithTrustedOrgs(orgs ...string) Option {
	return func(o *Options) {
		o.TrustedOrgs = append(o.TrustedOrgs, orgs...)
	}
}

// WithTrustedOrgUnits sets the trusted organizational unit values
func WithTrustedOrgUnits(ous ...string) Option {
	return func(o *Options) {
		o.TrustedOrgUnits = append(o.TrustedOrgUnits, ous...)
	}
}

// MTLSMiddleware creates a mutual TLS authentication middleware
func MTLSMiddleware(logger log.Logger, opts ...Option) middleware.Middleware {
	l := log.NewHelper(log.With(logger, "module", "middleware/mtls"))

	// Default options
	options := &Options{
		PublicEndpoints: []string{},
		TrustedOrgs:     []string{"LCM"},
		TrustedOrgUnits: []string{"LCM Certificate Authority", "LCM"},
	}

	for _, opt := range opts {
		opt(options)
	}

	return func(handler middleware.Handler) middleware.Handler {
		return func(ctx context.Context, req any) (any, error) {
			// Get the transport info to determine the operation
			if tr, ok := transport.FromServerContext(ctx); ok {
				operation := tr.Operation()

				// Extract peer information from gRPC context
				p, ok := peer.FromContext(ctx)
				if !ok {
					l.Error("Failed to get peer information from context")
					return nil, status.Error(codes.Unauthenticated, "failed to get peer information")
				}

				// Extract client certificate information if available
				clientInfo := extractClientInfo(p, l, options)

				// Skip mTLS for public endpoints
				if isPublicEndpoint(operation, options.PublicEndpoints) {
					l.Debugf("Skipping mTLS for public endpoint: %s", operation)
					// Still add client info to context even for public endpoints (may be nil)
					ctx = context.WithValue(ctx, ClientInfoKey, clientInfo)
					return handler(ctx, req)
				}

				l.Debugf("Validating client certificate for operation: %s", operation)

				// Validate client certificate for protected endpoints
				if clientInfo == nil || !clientInfo.IsAuthenticated {
					l.Error("Client certificate validation failed: no valid certificate")
					return nil, status.Error(codes.Unauthenticated, "client certificate required for this endpoint")
				}

				l.Debugf("Client certificate validated successfully for operation: %s (CN: %s)", operation, clientInfo.CommonName)

				// Add client info to context
				ctx = context.WithValue(ctx, ClientInfoKey, clientInfo)
			}

			return handler(ctx, req)
		}
	}
}

// isPublicEndpoint checks if the given operation is a public endpoint that doesn't require mTLS
func isPublicEndpoint(operation string, publicEndpoints []string) bool {
	return slices.Contains(publicEndpoints, operation)
}

// extractClientInfo extracts and validates client certificate information from peer
func extractClientInfo(p *peer.Peer, l *log.Helper, opts *Options) *ClientInfo {
	// Check if the connection has TLS info
	if p.AuthInfo == nil {
		l.Debug("No TLS authentication info available")
		return nil
	}

	// Cast to TLS credentials to access certificate information
	tlsInfo, ok := p.AuthInfo.(credentials.TLSInfo)
	if !ok {
		l.Debug("Failed to cast to TLS credentials")
		return nil
	}

	// Check if client certificates are present
	if len(tlsInfo.State.PeerCertificates) == 0 {
		l.Debug("No client certificates provided")
		return nil
	}

	// Get the first (leaf) certificate
	clientCert := tlsInfo.State.PeerCertificates[0]

	// Create client info struct
	clientInfo := &ClientInfo{
		Certificate:     clientCert,
		Subject:         clientCert.Subject.String(),
		Issuer:          clientCert.Issuer.String(),
		SerialNumber:    clientCert.SerialNumber.String(),
		CommonName:      clientCert.Subject.CommonName,
		Organizations:   clientCert.Subject.Organization,
		NotBefore:       clientCert.NotBefore,
		NotAfter:        clientCert.NotAfter,
		IsAuthenticated: false, // Will be set to true after validation
	}

	// Log certificate information for debugging
	l.Debugf("Client certificate Subject: %s", clientInfo.Subject)
	l.Debugf("Client certificate Issuer: %s", clientInfo.Issuer)
	l.Debugf("Client certificate Serial: %s", clientInfo.SerialNumber)

	// Validate certificate
	if err := validateCertificateValidity(clientCert); err != nil {
		l.Debugf("Certificate validity check failed: %v", err)
		return clientInfo // Return with IsAuthenticated = false
	}

	if err := validateCertificateIssuer(clientCert, opts); err != nil {
		l.Debugf("Certificate issuer validation failed: %v", err)
		return clientInfo // Return with IsAuthenticated = false
	}

	// Mark as authenticated if all validations pass
	clientInfo.IsAuthenticated = true
	l.Debugf("Client certificate validation successful")

	return clientInfo
}

// validateCertificateValidity checks if the certificate is currently valid
func validateCertificateValidity(cert *x509.Certificate) error {
	now := time.Now()
	if cert.NotBefore.After(now) {
		return fmt.Errorf("certificate not yet valid (NotBefore: %v)", cert.NotBefore)
	}
	if cert.NotAfter.Before(now) {
		return fmt.Errorf("certificate expired (NotAfter: %v)", cert.NotAfter)
	}
	return nil
}

// validateCertificateIssuer checks if the certificate was issued by a trusted CA
func validateCertificateIssuer(cert *x509.Certificate, opts *Options) error {
	// Check if the issuer contains expected organizational units
	issuerStr := cert.Issuer.String()
	if issuerStr == "" {
		return fmt.Errorf("certificate has no issuer information")
	}

	// Check organizational units
	for _, ou := range cert.Issuer.OrganizationalUnit {
		if slices.Contains(opts.TrustedOrgUnits, ou) {
			return nil // Valid issuer
		}
	}

	// Check organization as well
	for _, org := range cert.Issuer.Organization {
		if slices.Contains(opts.TrustedOrgs, org) {
			return nil // Valid issuer
		}
	}

	return fmt.Errorf("certificate not issued by trusted CA (issuer: %s)", issuerStr)
}

// ExtractClientCertificate extracts the client certificate from the context
func ExtractClientCertificate(ctx context.Context) (*x509.Certificate, error) {
	if cert, ok := GetClientCertificateFromContext(ctx); ok {
		return cert, nil
	}
	return nil, errors.New(401, "NO_CLIENT_CERT", "no client certificate found in context")
}
