package grpcx

import (
	"context"
	"crypto/subtle"
	"os"

	"google.golang.org/grpc"
	grpcMD "google.golang.org/grpc/metadata"
)

// ModuleSecretMetadataKey is the gRPC metadata key carrying the shared
// module-bootstrap secret on calls to the admin control plane (:7787).
//
// The admin gRPC registration port is plaintext and reachable across hosts
// (modules run on separate servers), so the registration/heartbeat/unregister
// RPCs and the internal user/role/credential RPCs served there are gated by
// this shared secret rather than by network isolation alone. It is the same
// value every module already holds as MODULE_BOOTSTRAP_SECRET for LCM cert
// bootstrap; presenting it here proves the caller is a platform module and
// not an arbitrary party that merely reached the TCP port.
const ModuleSecretMetadataKey = "x-registration-secret"

// EnvModuleBootstrapSecret is the environment variable holding the shared
// secret, mirroring go-tangra-common/cert.
const EnvModuleBootstrapSecret = "MODULE_BOOTSTRAP_SECRET"

// ModuleBootstrapSecret returns the configured shared secret from the
// environment, or the empty string when unset.
func ModuleBootstrapSecret() string {
	return os.Getenv(EnvModuleBootstrapSecret)
}

// ModuleSecretUnaryClientInterceptor attaches the module-bootstrap secret to
// every outgoing unary call as gRPC metadata. Attach it to any client
// connection that targets the admin :7787 control plane (the registration
// client and each module's admin API client). When the secret is unset the
// interceptor is a no-op, so it is safe to add unconditionally.
func ModuleSecretUnaryClientInterceptor() grpc.UnaryClientInterceptor {
	return func(
		ctx context.Context,
		method string,
		req, reply any,
		cc *grpc.ClientConn,
		invoker grpc.UnaryInvoker,
		opts ...grpc.CallOption,
	) error {
		if secret := ModuleBootstrapSecret(); secret != "" {
			ctx = grpcMD.AppendToOutgoingContext(ctx, ModuleSecretMetadataKey, secret)
		}
		return invoker(ctx, method, req, reply, cc, opts...)
	}
}

// GetModuleSecretFromContext returns the module secret presented on an
// incoming call's metadata, if any.
func GetModuleSecretFromContext(ctx context.Context) string {
	return GetMetadataValue(ctx, ModuleSecretMetadataKey)
}

// ValidateModuleSecret reports whether the secret presented on the incoming
// call matches expected, using a constant-time comparison. An empty expected
// secret always fails, so a misconfigured server (no secret set) never
// silently accepts everyone.
func ValidateModuleSecret(ctx context.Context, expected string) bool {
	if expected == "" {
		return false
	}
	got := GetModuleSecretFromContext(ctx)
	return subtle.ConstantTimeCompare([]byte(got), []byte(expected)) == 1
}
