package audit

import (
	"context"
	"crypto/ecdsa"
)

// WriteAuditLogFunc is the function signature for writing audit logs
type WriteAuditLogFunc func(ctx context.Context, log *AuditLog) error

type options struct {
	writeAuditLogFunc WriteAuditLogFunc

	// Operations to skip logging (e.g., health checks)
	skipOperations map[string]bool

	// EC keys for cryptographic signing
	ecPrivateKey *ecdsa.PrivateKey
	ecPublicKey  *ecdsa.PublicKey

	// Service name for audit log source identification
	serviceName string
}

// Option configures the audit middleware
type Option func(*options)

// WithWriteAuditLogFunc sets the function to write audit logs
func WithWriteAuditLogFunc(fnc WriteAuditLogFunc) Option {
	return func(opts *options) {
		opts.writeAuditLogFunc = fnc
	}
}

// WithSkipOperations sets operations to skip logging
func WithSkipOperations(operations ...string) Option {
	return func(opts *options) {
		if opts.skipOperations == nil {
			opts.skipOperations = make(map[string]bool)
		}
		for _, op := range operations {
			opts.skipOperations[op] = true
		}
	}
}

// WithECPrivateKey sets the ECDSA private key for signing
func WithECPrivateKey(key *ecdsa.PrivateKey) Option {
	return func(opts *options) {
		opts.ecPrivateKey = key
	}
}

// WithECPublicKey sets the ECDSA public key for verification
func WithECPublicKey(key *ecdsa.PublicKey) Option {
	return func(opts *options) {
		opts.ecPublicKey = key
	}
}

// WithServiceName sets the service name for audit log identification
func WithServiceName(name string) Option {
	return func(opts *options) {
		opts.serviceName = name
	}
}
