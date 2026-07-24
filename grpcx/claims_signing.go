package grpcx

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"strconv"
	"time"

	grpcMD "google.golang.org/grpc/metadata"
)

// Claim-binding metadata keys. These carry a gateway-produced HMAC over the
// x-md-global-* user claims so a module can prove the claims originated from the
// gateway rather than being forged by a direct mTLS caller (CRIT-3.2 / MED-2).
// They use the x-md-global- prefix so they auto-propagate across module hops
// alongside the claims they authenticate — a downstream module re-verifies the
// same signature without the gateway re-signing.
const (
	// MDClaimsSig is the hex-encoded HMAC-SHA256 over the canonical claim tuple.
	MDClaimsSig = "x-md-global-claims-sig"
	// MDClaimsExp is the unix-seconds expiry of the assertion.
	MDClaimsExp = "x-md-global-claims-exp"
)

// signedClaimKeys are the user-identity claims the signature covers and that are
// stripped when an assertion is missing or invalid under enforce mode.
var signedClaimKeys = []string{MDTenantID, MDUserID, MDUsername, MDRoles}

// canonicalClaimMessage builds the exact byte sequence signed by the gateway and
// re-verified by modules. Values are the raw metadata strings joined by newlines;
// newline cannot appear in a gRPC/HTTP header value, so the encoding is
// unambiguous. Signer and verifier MUST agree byte-for-byte, so this is the one
// source of truth for the layout.
func canonicalClaimMessage(tenantID, userID, username, roles string, exp int64) []byte {
	msg := tenantID + "\n" + userID + "\n" + username + "\n" + roles + "\n" + strconv.FormatInt(exp, 10)
	return []byte(msg)
}

// SignClaims returns the hex HMAC-SHA256 of the canonical claim tuple. The
// gateway calls this after deriving claims from the verified user JWT and sets
// the result as MDClaimsSig (with MDClaimsExp = exp).
func SignClaims(secret []byte, tenantID, userID, username, roles string, exp int64) string {
	mac := hmac.New(sha256.New, secret)
	mac.Write(canonicalClaimMessage(tenantID, userID, username, roles, exp))
	return hex.EncodeToString(mac.Sum(nil))
}

// HasUserClaims reports whether the incoming metadata carries any user-identity
// claim at all. Service-to-service and health calls carry none, so there is
// nothing to verify or strip for them.
func HasUserClaims(md grpcMD.MD) bool {
	for _, k := range signedClaimKeys {
		if vals := md.Get(k); len(vals) > 0 && vals[0] != "" {
			return true
		}
	}
	return false
}

// VerifyClaimsSignature checks that the x-md-global-* user claims in the incoming
// context are covered by a valid, unexpired gateway HMAC. It returns true only
// when the signature matches and has not expired. An empty secret always returns
// false (fail closed). now is injected for testability.
func VerifyClaimsSignature(md grpcMD.MD, secret []byte, now time.Time) bool {
	if len(secret) == 0 {
		return false
	}

	sig := firstMD(md, MDClaimsSig)
	if sig == "" {
		return false
	}
	expStr := firstMD(md, MDClaimsExp)
	exp, err := strconv.ParseInt(expStr, 10, 64)
	if err != nil {
		return false
	}
	if now.Unix() > exp {
		return false // assertion expired
	}

	want := SignClaims(
		secret,
		firstMD(md, MDTenantID),
		firstMD(md, MDUserID),
		firstMD(md, MDUsername),
		firstMD(md, MDRoles),
		exp,
	)
	// hex strings of equal length; constant-time compare guards the secret.
	return hmac.Equal([]byte(sig), []byte(want))
}

// firstMD returns the first value for key or "" when absent.
func firstMD(md grpcMD.MD, key string) string {
	if vals := md.Get(key); len(vals) > 0 {
		return vals[0]
	}
	return ""
}

// StripUserClaims returns a copy of ctx whose incoming metadata has all
// user-identity claims and the (now meaningless) assertion removed. Downstream
// authz then sees no roles/tenant/user — IsPlatformAdmin becomes false — so a
// forged or unauthenticated claim set is ignored rather than trusted.
func StripUserClaims(ctx context.Context) context.Context {
	md, ok := grpcMD.FromIncomingContext(ctx)
	if !ok {
		return ctx
	}
	stripped := md.Copy()
	for _, k := range signedClaimKeys {
		stripped.Delete(k)
	}
	stripped.Delete(MDClaimsSig)
	stripped.Delete(MDClaimsExp)
	return grpcMD.NewIncomingContext(ctx, stripped)
}
