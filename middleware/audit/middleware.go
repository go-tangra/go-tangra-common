package audit

import (
	"context"
	"net"
	"strings"
	"time"

	"github.com/go-kratos/kratos/v2/errors"
	"github.com/go-kratos/kratos/v2/log"
	"github.com/go-kratos/kratos/v2/middleware"
	"github.com/go-kratos/kratos/v2/transport"
	"github.com/google/uuid"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"

	"github.com/go-tangra/go-tangra-common/middleware/mtls"
)

const (
	// Default service name
	defaultServiceName = "unknown-service"

	// Metadata keys
	metadataKeyRequestID = "x-request-id"
)

// Server creates a server-side audit logging middleware for gRPC
func Server(logger log.Logger, opts ...Option) middleware.Middleware {
	l := log.NewHelper(log.With(logger, "module", "middleware/audit"))

	op := options{
		serviceName:    defaultServiceName,
		skipOperations: make(map[string]bool),
	}

	for _, o := range opts {
		o(&op)
	}

	// Generate EC keys if not provided
	if op.ecPrivateKey == nil || op.ecPublicKey == nil {
		var err error
		op.ecPrivateKey, op.ecPublicKey, err = GenerateECDSAKeyPair()
		if err != nil {
			l.Errorf("Failed to generate ECDSA key pair: %v", err)
		} else {
			l.Info("Generated new ECDSA key pair for audit log signing")
		}
	}

	return func(handler middleware.Handler) middleware.Handler {
		return func(ctx context.Context, req interface{}) (reply interface{}, err error) {
			startTime := time.Now()

			// Execute the handler
			reply, err = handler(ctx, req)

			// Calculate latency
			latencyMs := time.Since(startTime).Milliseconds()

			// Get transport info
			tr, ok := transport.FromServerContext(ctx)
			if !ok {
				return reply, err
			}

			operation := tr.Operation()

			// Skip logging for specified operations
			if op.skipOperations[operation] {
				return reply, err
			}

			// Build audit log
			auditLog := buildAuditLog(ctx, &op, operation, latencyMs, err)

			// Compute hash and signature
			auditLog.LogHash = HashLog(auditLog)
			if op.ecPrivateKey != nil {
				sig, signErr := SignLog(auditLog, op.ecPrivateKey)
				if signErr != nil {
					l.Warnf("Failed to sign audit log: %v", signErr)
				} else {
					auditLog.Signature = sig
				}
			}

			// Write audit log
			if op.writeAuditLogFunc != nil {
				if writeErr := op.writeAuditLogFunc(ctx, auditLog); writeErr != nil {
					l.Errorf("Failed to write audit log: %v", writeErr)
				}
			} else {
				// Default: log to standard logger
				l.Infow(
					"audit_id", auditLog.ID,
					"operation", auditLog.Operation,
					"client_id", auditLog.ClientID,
					"tenant_id", auditLog.TenantID,
					"success", auditLog.Success,
					"latency_ms", auditLog.LatencyMs,
					"peer_address", auditLog.PeerAddress,
				)
			}

			return reply, err
		}
	}
}

// buildAuditLog constructs an AuditLog from the request context
func buildAuditLog(ctx context.Context, op *options, operation string, latencyMs int64, err error) *AuditLog {
	auditLog := &AuditLog{
		ID:          uuid.New().String(),
		Timestamp:   time.Now().UTC(),
		LatencyMs:   latencyMs,
		Operation:   operation,
		ServiceName: op.serviceName,
		Success:     err == nil,
	}

	// Extract request ID from metadata
	if md, ok := metadata.FromIncomingContext(ctx); ok {
		if vals := md.Get(metadataKeyRequestID); len(vals) > 0 {
			auditLog.RequestID = vals[0]
		}
	}

	// Extract client info from mTLS middleware
	if clientInfo, ok := mtls.GetClientInfoFromContext(ctx); ok && clientInfo != nil {
		auditLog.ClientID = clientInfo.CommonName
		auditLog.ClientCommonName = clientInfo.CommonName
		auditLog.ClientSerialNumber = clientInfo.SerialNumber
		auditLog.IsAuthenticated = clientInfo.IsAuthenticated
		auditLog.TenantID = clientInfo.TenantID

		if len(clientInfo.Organizations) > 0 {
			auditLog.ClientOrganization = strings.Join(clientInfo.Organizations, ", ")
		}
	}

	// Extract peer address
	if p, ok := peer.FromContext(ctx); ok && p.Addr != nil {
		auditLog.PeerAddress = extractIP(p.Addr.String())
	}

	// Extract error info
	if err != nil {
		auditLog.Success = false
		if se := errors.FromError(err); se != nil {
			auditLog.ErrorCode = se.Code
			auditLog.ErrorMessage = se.Message
		} else {
			auditLog.ErrorMessage = err.Error()
		}
	}

	return auditLog
}

// extractIP extracts IP address from address string (removes port)
func extractIP(addr string) string {
	if addr == "" {
		return ""
	}

	// Handle IPv6 addresses
	if strings.HasPrefix(addr, "[") {
		if idx := strings.Index(addr, "]:"); idx != -1 {
			return addr[1:idx]
		}
		return strings.TrimPrefix(strings.TrimSuffix(addr, "]"), "[")
	}

	// Handle IPv4 addresses
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return addr
	}
	return host
}

// GetPublicKey returns the public key for signature verification
// This can be used by external systems to verify audit log integrity
func GetPublicKey(opts ...Option) interface{} {
	op := options{}
	for _, o := range opts {
		o(&op)
	}
	return op.ecPublicKey
}
