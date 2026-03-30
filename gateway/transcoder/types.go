package transcoder

import (
	"context"
	"net/http"

	"google.golang.org/grpc/metadata"
)

// RouteInfo contains information about a registered route.
type RouteInfo struct {
	ModuleID    string
	ServiceName string
	MethodName  string
	HTTPMethod  string
	Pattern     string
	FullMethod  string
}

// HTTPError represents an HTTP error response.
type HTTPError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Details any    `json:"details,omitempty"`
}

// AuditLogEntry is a generic, framework-agnostic audit log entry
// for a transcoded HTTP-to-gRPC request.
type AuditLogEntry struct {
	ModuleID    string
	Method      string // gRPC full method name (empty if method resolution failed)
	HTTPMethod  string
	Path        string
	StatusCode  int
	Reason      string
	LatencyMs   int64
	ClientIP    string
	RequestID   string
	RequestBody []byte
	// Request is the original HTTP request for implementors that need
	// additional detail (headers, auth tokens, etc.).
	Request *http.Request
}

// AuthContextProvider extracts auth info from an HTTP request context.
type AuthContextProvider interface {
	// GetTenantID returns the tenant ID from the request context.
	GetTenantID(ctx context.Context) (uint32, bool)
	// InjectGRPCMetadata builds outgoing gRPC metadata from the auth context.
	InjectGRPCMetadata(ctx context.Context, r *http.Request) metadata.MD
}

// AuditLogWriter writes audit log entries for transcoded requests.
type AuditLogWriter interface {
	WriteAuditLog(ctx context.Context, entry *AuditLogEntry) error
}
