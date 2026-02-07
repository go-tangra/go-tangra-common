package audit

import (
	"time"
)

// AuditLog represents a single audit log entry for gRPC operations
type AuditLog struct {
	// Identifiers
	ID        string `json:"id"`
	RequestID string `json:"request_id,omitempty"`

	// Timing
	Timestamp time.Time `json:"timestamp"`
	LatencyMs int64     `json:"latency_ms"`

	// Operation info
	Operation   string `json:"operation"`
	ServiceName string `json:"service_name"`

	// Client info (from mTLS)
	ClientID           string `json:"client_id,omitempty"`
	ClientCommonName   string `json:"client_common_name,omitempty"`
	ClientOrganization string `json:"client_organization,omitempty"`
	ClientSerialNumber string `json:"client_serial_number,omitempty"`
	IsAuthenticated    bool   `json:"is_authenticated"`

	// Tenant info
	TenantID uint32 `json:"tenant_id,omitempty"`

	// Request/Response
	Success      bool   `json:"success"`
	ErrorCode    int32  `json:"error_code,omitempty"`
	ErrorMessage string `json:"error_message,omitempty"`

	// Network info
	PeerAddress string `json:"peer_address,omitempty"`

	// Geo location (optional)
	GeoLocation *GeoLocation `json:"geo_location,omitempty"`

	// Cryptographic integrity
	LogHash   string `json:"log_hash,omitempty"`
	Signature []byte `json:"signature,omitempty"`

	// Additional metadata
	Metadata map[string]string `json:"metadata,omitempty"`
}

// GeoLocation represents geographic location information
type GeoLocation struct {
	CountryCode string `json:"country_code,omitempty"`
	Province    string `json:"province,omitempty"`
	City        string `json:"city,omitempty"`
	ISP         string `json:"isp,omitempty"`
}

// SignContent is the structure used for signature generation
// It contains the critical fields that must not be tampered with
type SignContent struct {
	TenantID  uint32 `json:"tenant_id"`
	ClientID  string `json:"client_id"`
	Operation string `json:"operation"`
	Timestamp int64  `json:"timestamp"` // Unix nanoseconds
	LogHash   string `json:"log_hash"`
}

// AuditLogEntry is the input structure for database repository
type AuditLogEntry struct {
	AuditID            string
	RequestID          string
	TenantID           uint32
	Operation          string
	ServiceName        string
	ClientID           string
	ClientCommonName   string
	ClientOrganization string
	ClientSerialNumber string
	IsAuthenticated    bool
	Success            bool
	ErrorCode          int32
	ErrorMessage       string
	LatencyMs          int64
	PeerAddress        string
	GeoLocation        map[string]string
	LogHash            string
	Signature          []byte
	Metadata           map[string]string
	Timestamp          time.Time
}

// ToEntry converts AuditLog to AuditLogEntry for database storage
func (a *AuditLog) ToEntry() *AuditLogEntry {
	entry := &AuditLogEntry{
		AuditID:            a.ID,
		RequestID:          a.RequestID,
		TenantID:           a.TenantID,
		Operation:          a.Operation,
		ServiceName:        a.ServiceName,
		ClientID:           a.ClientID,
		ClientCommonName:   a.ClientCommonName,
		ClientOrganization: a.ClientOrganization,
		ClientSerialNumber: a.ClientSerialNumber,
		IsAuthenticated:    a.IsAuthenticated,
		Success:            a.Success,
		ErrorCode:          a.ErrorCode,
		ErrorMessage:       a.ErrorMessage,
		LatencyMs:          a.LatencyMs,
		PeerAddress:        a.PeerAddress,
		LogHash:            a.LogHash,
		Signature:          a.Signature,
		Metadata:           a.Metadata,
		Timestamp:          a.Timestamp,
	}

	// Convert GeoLocation to map if present
	if a.GeoLocation != nil {
		entry.GeoLocation = map[string]string{
			"country_code": a.GeoLocation.CountryCode,
			"province":     a.GeoLocation.Province,
			"city":         a.GeoLocation.City,
			"isp":          a.GeoLocation.ISP,
		}
	}

	return entry
}
