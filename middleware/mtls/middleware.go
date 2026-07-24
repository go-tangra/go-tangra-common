package mtls

import (
	"context"
	"crypto/x509"
	"fmt"
	"os"
	"slices"
	"strings"
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

// EnvIdentityMode is the environment variable controlling the mTLS peer-identity
// allow-list rollout: off | warn | enforce (default warn).
const EnvIdentityMode = "MTLS_IDENTITY_MODE"

// EnvAllowedIdentities is a comma-separated list of extra caller CNs merged
// into the compiled-in allow-list. It is an operational escape hatch so a
// missing legitimate caller can be permitted without a rebuild.
const EnvAllowedIdentities = "MTLS_ALLOWED_IDENTITIES"

// Identity-check rollout modes. mTLS validates the certificate issuer (any
// LCM-signed cert is accepted) unconditionally; these modes additionally gate
// on the caller's Common Name matching a configured allow-list.
const (
	// IdentityModeOff disables the CN allow-list entirely (issuer-only,
	// legacy behaviour).
	IdentityModeOff = "off"
	// IdentityModeWarn logs callers whose CN is not in the allow-list but
	// still authenticates them. Safe default while modules are redeployed
	// with matching client certs.
	IdentityModeWarn = "warn"
	// IdentityModeEnforce rejects callers whose CN is not in the allow-list.
	IdentityModeEnforce = "enforce"
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

	// AllowedCommonNames is the allow-list of caller certificate Common Names
	// permitted to reach protected endpoints. Legitimate module client certs
	// have CN "lcm-<moduleID>" (see go-tangra-common/cert). When empty, the
	// CN allow-list is disabled and validation falls back to issuer-only —
	// preserving legacy behaviour for callers that have not configured it.
	AllowedCommonNames []string

	// IdentityMode controls how a CN that is not in AllowedCommonNames is
	// handled: off | warn | enforce. When empty it is read from the
	// MTLS_IDENTITY_MODE environment variable, defaulting to "warn".
	IdentityMode string
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

// WithAllowedIdentities restricts protected endpoints to callers whose client
// certificate Common Name is in cns. Module client certs use CN
// "lcm-<moduleID>", so a module reachable only from the gateway would pass
// WithAllowedIdentities("lcm-<gatewayModuleID>"). When no identities are
// configured the allow-list is disabled (issuer-only validation).
func WithAllowedIdentities(cns ...string) Option {
	return func(o *Options) {
		o.AllowedCommonNames = append(o.AllowedCommonNames, cns...)
	}
}

// WithIdentityMode overrides the CN allow-list rollout mode
// (off | warn | enforce). When unset the MTLS_IDENTITY_MODE environment
// variable is used, defaulting to "warn".
func WithIdentityMode(mode string) Option {
	return func(o *Options) {
		o.IdentityMode = mode
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

	// Resolve the identity-check mode: explicit option wins, else env, else warn.
	if options.IdentityMode == "" {
		options.IdentityMode = os.Getenv(EnvIdentityMode)
	}
	if options.IdentityMode == "" {
		options.IdentityMode = IdentityModeWarn
	}
	// Merge any operator-provided extra identities from the environment.
	for cn := range strings.SplitSeq(os.Getenv(EnvAllowedIdentities), ",") {
		if cn = strings.TrimSpace(cn); cn != "" {
			options.AllowedCommonNames = append(options.AllowedCommonNames, cn)
		}
	}
	if len(options.AllowedCommonNames) > 0 {
		l.Infof("mTLS peer-identity allow-list active (mode=%s, %d identities)", options.IdentityMode, len(options.AllowedCommonNames))
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

				// Validate client certificate for protected endpoints
				if clientInfo == nil || !clientInfo.IsAuthenticated {
					l.Error("Client certificate validation failed: no valid certificate")
					return nil, status.Error(codes.Unauthenticated, "client certificate required for this endpoint")
				}
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

	// Validate certificate
	if err := validateCertificateValidity(clientCert); err != nil {
		l.Debugf("Certificate validity check failed: %v", err)
		return clientInfo // Return with IsAuthenticated = false
	}

	if err := validateCertificateIssuer(clientCert, opts); err != nil {
		l.Debugf("Certificate issuer validation failed: %v", err)
		return clientInfo // Return with IsAuthenticated = false
	}

	if err := validateCertificateIdentity(clientCert, opts, l); err != nil {
		l.Debugf("Certificate identity validation failed: %v", err)
		return clientInfo // Return with IsAuthenticated = false
	}

	// Mark as authenticated if all validations pass
	clientInfo.IsAuthenticated = true
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

// validateCertificateIdentity checks the caller's certificate Common Name
// against the configured allow-list. It is a no-op when no allow-list is set
// (AllowedCommonNames empty) or when the mode is "off", preserving issuer-only
// behaviour. In "warn" mode a non-listed CN is logged but accepted; in
// "enforce" mode it is rejected.
func validateCertificateIdentity(cert *x509.Certificate, opts *Options, l *log.Helper) error {
	if len(opts.AllowedCommonNames) == 0 || opts.IdentityMode == IdentityModeOff {
		return nil
	}

	cn := cert.Subject.CommonName
	if slices.Contains(opts.AllowedCommonNames, cn) {
		return nil // Recognised peer identity
	}

	if opts.IdentityMode == IdentityModeEnforce {
		return fmt.Errorf("caller certificate CN %q is not an allowed identity", cn)
	}

	// warn mode: record but accept, so a not-yet-redeployed caller keeps working.
	l.Warnf("mTLS caller CN %q not in allowed identities (accepted: mode=warn)", cn)
	return nil
}

// ExtractClientCertificate extracts the client certificate from the context
func ExtractClientCertificate(ctx context.Context) (*x509.Certificate, error) {
	if cert, ok := GetClientCertificateFromContext(ctx); ok {
		return cert, nil
	}
	return nil, errors.New(401, "NO_CLIENT_CERT", "no client certificate found in context")
}
