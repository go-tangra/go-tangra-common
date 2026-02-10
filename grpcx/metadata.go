package grpcx

import (
	"context"
	"strconv"

	grpcMD "google.golang.org/grpc/metadata"
)

// Metadata keys using Kratos x-md-global- prefix for cross-service propagation.
// These are set by the admin-service transcoder and forwarded via gRPC metadata.
const (
	MDTenantID = "x-md-global-tenant-id"
	MDUserID   = "x-md-global-user-id"
	MDUsername  = "x-md-global-username"
	MDRoles    = "x-md-global-roles"
	MDClientIP = "x-client-ip"
)

// GetMetadataValue extracts a single value from gRPC incoming metadata
func GetMetadataValue(ctx context.Context, key string) string {
	md, ok := grpcMD.FromIncomingContext(ctx)
	if !ok {
		return ""
	}
	vals := md.Get(key)
	if len(vals) == 0 {
		return ""
	}
	return vals[0]
}

// GetTenantIDFromContext extracts the tenant ID from gRPC metadata
func GetTenantIDFromContext(ctx context.Context) uint32 {
	tenantStr := GetMetadataValue(ctx, MDTenantID)
	if tenantStr == "" {
		return 0
	}

	tenantID, err := strconv.ParseUint(tenantStr, 10, 32)
	if err != nil {
		return 0
	}

	return uint32(tenantID)
}

// GetUserIDFromContext extracts the user ID as a string from gRPC metadata
func GetUserIDFromContext(ctx context.Context) string {
	return GetMetadataValue(ctx, MDUserID)
}

// GetUserIDAsUint32 extracts the user ID as uint32 pointer from gRPC metadata
func GetUserIDAsUint32(ctx context.Context) *uint32 {
	userStr := GetUserIDFromContext(ctx)
	if userStr == "" {
		return nil
	}

	userID, err := strconv.ParseUint(userStr, 10, 32)
	if err != nil {
		return nil
	}

	id := uint32(userID)
	return &id
}

// GetUsernameFromContext extracts the username from gRPC metadata
func GetUsernameFromContext(ctx context.Context) string {
	return GetMetadataValue(ctx, MDUsername)
}

// GetRolesFromContext extracts the roles from gRPC metadata (comma-separated)
func GetRolesFromContext(ctx context.Context) []string {
	rolesStr := GetMetadataValue(ctx, MDRoles)
	if rolesStr == "" {
		return nil
	}

	var roles []string
	start := 0
	for i := 0; i < len(rolesStr); i++ {
		if rolesStr[i] == ',' {
			role := rolesStr[start:i]
			if role != "" {
				roles = append(roles, role)
			}
			start = i + 1
		}
	}
	// Add the last part
	if start < len(rolesStr) {
		role := rolesStr[start:]
		if role != "" {
			roles = append(roles, role)
		}
	}
	return roles
}

// GetClientIPFromContext extracts the client IP from gRPC metadata
func GetClientIPFromContext(ctx context.Context) string {
	return GetMetadataValue(ctx, MDClientIP)
}

// IsPlatformAdmin checks if the user has platform admin role
func IsPlatformAdmin(ctx context.Context) bool {
	roles := GetRolesFromContext(ctx)
	for _, role := range roles {
		if role == "platform:admin" || role == "super:admin" {
			return true
		}
	}
	return false
}
