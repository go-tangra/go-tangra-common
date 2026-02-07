package mtls

import (
	"context"
	"crypto/x509"
	"time"
)

// ClientInfo contains information about the authenticated client
type ClientInfo struct {
	Certificate     *x509.Certificate `json:"-"` // Don't serialize the certificate
	Subject         string            `json:"subject"`
	Issuer          string            `json:"issuer"`
	SerialNumber    string            `json:"serial_number"`
	CommonName      string            `json:"common_name"`
	Organizations   []string          `json:"organizations"`
	NotBefore       time.Time         `json:"not_before"`
	NotAfter        time.Time         `json:"not_after"`
	IsAuthenticated bool              `json:"is_authenticated"`
	TenantID        uint32            `json:"tenant_id"` // Tenant ID associated with this client
}

// Context key for storing client information
type contextKey string

const ClientInfoKey contextKey = "client_info"

// GetClientInfoFromContext extracts client information from the request context
func GetClientInfoFromContext(ctx context.Context) (*ClientInfo, bool) {
	if clientInfo, ok := ctx.Value(ClientInfoKey).(*ClientInfo); ok && clientInfo != nil {
		return clientInfo, true
	}
	return nil, false
}

// GetClientCertificateFromContext extracts the client certificate from the request context
func GetClientCertificateFromContext(ctx context.Context) (*x509.Certificate, bool) {
	if clientInfo, ok := GetClientInfoFromContext(ctx); ok && clientInfo.Certificate != nil {
		return clientInfo.Certificate, true
	}
	return nil, false
}

// IsClientAuthenticated checks if the client is authenticated via mTLS
func IsClientAuthenticated(ctx context.Context) bool {
	if clientInfo, ok := GetClientInfoFromContext(ctx); ok {
		return clientInfo.IsAuthenticated
	}
	return false
}

// GetClientID extracts the client ID (CommonName) from the context
func GetClientID(ctx context.Context) string {
	if clientInfo, ok := GetClientInfoFromContext(ctx); ok && clientInfo.CommonName != "" {
		return clientInfo.CommonName
	}
	return ""
}

// GetTenantID extracts the tenant ID from the context
func GetTenantID(ctx context.Context) uint32 {
	if clientInfo, ok := GetClientInfoFromContext(ctx); ok {
		return clientInfo.TenantID
	}
	return 0
}

// SetClientInfoInContext stores client information in the context
func SetClientInfoInContext(ctx context.Context, clientInfo *ClientInfo) context.Context {
	return context.WithValue(ctx, ClientInfoKey, clientInfo)
}

// UpdateTenantID updates the tenant ID in the client info stored in context
// Returns a new context with the updated client info
func UpdateTenantID(ctx context.Context, tenantID uint32) context.Context {
	if clientInfo, ok := GetClientInfoFromContext(ctx); ok {
		// Create a copy with updated tenant ID
		updatedInfo := *clientInfo
		updatedInfo.TenantID = tenantID
		return SetClientInfoInContext(ctx, &updatedInfo)
	}
	// If no client info, create a minimal one with just tenant ID
	return SetClientInfoInContext(ctx, &ClientInfo{TenantID: tenantID})
}

// SetTenantIDInPlace updates the tenant ID in the existing ClientInfo pointer
// This modifies the ClientInfo in-place so that middleware running after the handler
// can see the updated tenant ID. This is needed because Go contexts are immutable.
func SetTenantIDInPlace(ctx context.Context, tenantID uint32) {
	if clientInfo, ok := GetClientInfoFromContext(ctx); ok && clientInfo != nil {
		clientInfo.TenantID = tenantID
	}
}
