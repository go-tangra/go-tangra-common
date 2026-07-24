// Package claims provides a gRPC server middleware that binds the caller's
// x-md-global-* user claims (roles/tenant/user) to a gateway-produced HMAC
// assertion. Without it, any authenticated mTLS peer can forge these claims —
// e.g. set x-md-global-roles: platform:admin on a direct connection — because
// the claims are independent of the peer identity (CRIT-3.2 / MED-2). The
// gateway signs the claims it derives from the verified user JWT; modules
// verify that signature and ignore (strip) any claims that are not covered.
package claims

import (
	"context"
	"os"
	"time"

	"github.com/go-kratos/kratos/v2/log"
	"github.com/go-kratos/kratos/v2/middleware"
	"github.com/go-kratos/kratos/v2/transport"
	grpcMD "google.golang.org/grpc/metadata"

	"github.com/go-tangra/go-tangra-common/grpcx"
)

// EnvSigningSecret is the shared secret the gateway signs with and modules
// verify against. It must match the gateway's CLAIMS_SIGNING_SECRET.
const EnvSigningSecret = "CLAIMS_SIGNING_SECRET"

// EnvBindingMode controls the rollout: off | warn | enforce (default warn).
const EnvBindingMode = "CLAIMS_BINDING_MODE"

// Rollout modes for the claims-binding check.
const (
	// ModeOff disables the check entirely (legacy: raw claims trusted).
	ModeOff = "off"
	// ModeWarn logs when incoming claims lack a valid assertion but still
	// passes the claims through, so the platform keeps working while the
	// gateway is redeployed to sign and modules to verify.
	ModeWarn = "warn"
	// ModeEnforce strips unverified user claims from the request context, so
	// forged claims are ignored and authorization sees no roles/tenant/user.
	ModeEnforce = "enforce"
)

// Options configures the middleware.
type Options struct {
	// Secret is the HMAC key shared with the gateway. When empty it is read
	// from CLAIMS_SIGNING_SECRET.
	Secret []byte
	// Mode is off | warn | enforce. When empty it is read from
	// CLAIMS_BINDING_MODE, defaulting to warn.
	Mode string
}

// Option configures Options.
type Option func(*Options)

// WithSecret sets the HMAC verification key explicitly.
func WithSecret(secret []byte) Option {
	return func(o *Options) { o.Secret = secret }
}

// WithMode overrides the rollout mode (off | warn | enforce).
func WithMode(mode string) Option {
	return func(o *Options) { o.Mode = mode }
}

// Server returns a Kratos middleware that verifies the gateway's claim
// assertion. Place it AFTER metadata.Server() (so incoming metadata is parsed)
// and before the service handlers. It is a no-op for requests that carry no
// user claims (service-to-service, health).
func Server(logger log.Logger, opts ...Option) middleware.Middleware {
	l := log.NewHelper(log.With(logger, "module", "middleware/claims"))

	options := &Options{}
	for _, opt := range opts {
		opt(options)
	}
	if len(options.Secret) == 0 {
		options.Secret = []byte(os.Getenv(EnvSigningSecret))
	}
	if options.Mode == "" {
		options.Mode = os.Getenv(EnvBindingMode)
	}
	if options.Mode == "" {
		options.Mode = ModeWarn
	}

	if options.Mode != ModeOff && len(options.Secret) == 0 {
		// Fail loud: enforce/warn without a key can never verify a signature,
		// so every request would look forged. Surface it rather than silently
		// stripping every caller's claims.
		l.Errorf("claims-binding mode=%s but %s is empty; assertions cannot be verified", options.Mode, EnvSigningSecret)
	} else if options.Mode != ModeOff {
		l.Infof("claims-binding active (mode=%s)", options.Mode)
	}

	return func(handler middleware.Handler) middleware.Handler {
		return func(ctx context.Context, req any) (any, error) {
			if options.Mode == ModeOff {
				return handler(ctx, req)
			}

			md, ok := grpcMD.FromIncomingContext(ctx)
			if !ok {
				return handler(ctx, req) // no metadata: nothing to verify
			}

			// Only user-identity claims are security-relevant. Service and
			// health calls carry none and need no assertion.
			if !grpcx.HasUserClaims(md) {
				return handler(ctx, req)
			}

			if grpcx.VerifyClaimsSignature(md, options.Secret, nowFn()) {
				return handler(ctx, req) // claims authenticated by the gateway
			}

			op := ""
			if tr, tok := transport.FromServerContext(ctx); tok {
				op = tr.Operation()
			}

			if options.Mode == ModeEnforce {
				l.Warnf("stripping unverified user claims (op=%s): no valid gateway assertion", op)
				return handler(grpcx.StripUserClaims(ctx), req)
			}

			// warn: record but pass the raw claims through during rollout.
			l.Warnf("incoming user claims lack a valid gateway assertion (op=%s, mode=warn, claims trusted)", op)
			return handler(ctx, req)
		}
	}
}

// nowFn is overridable in tests; production uses the wall clock.
var nowFn = func() time.Time { return time.Now() }
