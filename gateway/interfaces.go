package gateway

import (
	"context"
	"net/http"

	"google.golang.org/grpc/metadata"
)

// AuthContextProvider extracts auth info from an HTTP request context.
// Implementations read framework-specific claims (e.g. JWT) and produce
// the tenant ID and gRPC metadata needed for module transcoding.
type AuthContextProvider interface {
	// GetTenantID returns the tenant ID from the request context.
	// Returns (0, false) if not available.
	GetTenantID(ctx context.Context) (uint32, bool)

	// InjectGRPCMetadata builds outgoing gRPC metadata from the HTTP request's
	// auth context (user ID, tenant ID, roles, etc.).
	InjectGRPCMetadata(ctx context.Context, r *http.Request) metadata.MD
}

// AuditLogWriter writes audit log entries for transcoded requests.
// Implementations handle persistence, enrichment (GeoIP, device info),
// and cryptographic signing as needed.
type AuditLogWriter interface {
	WriteAuditLog(ctx context.Context, entry *AuditLogEntry) error
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

// ModuleEventType represents the type of module registry event.
type ModuleEventType int

const (
	ModuleEventRegistered ModuleEventType = iota
	ModuleEventUnregistered
	ModuleEventUpdated
	ModuleEventHealthChanged
)

// ModuleInfo is the subset of module data needed by the router and transcoder.
type ModuleInfo struct {
	ModuleID        string
	GrpcEndpoint    string
	ProtoDescriptor []byte
	Health          string
}

// ModuleEvent represents a module lifecycle event.
type ModuleEvent struct {
	Type   ModuleEventType
	Module *ModuleInfo
}

// ModuleEventHandler is a callback function for module events.
type ModuleEventHandler func(event ModuleEvent)

// ModuleRegistry provides module lookup and lifecycle event subscription.
type ModuleRegistry interface {
	// Get returns a module by its ID. Returns (nil, false) if not found.
	Get(moduleID string) (*ModuleInfo, bool)
	// List returns all registered modules.
	List() []*ModuleInfo
	// OnEvent registers a handler for module lifecycle events.
	OnEvent(handler ModuleEventHandler)
}
