package grpcx

import (
	"context"
	"testing"
	"time"

	grpcMD "google.golang.org/grpc/metadata"
)

func TestSignVerifyRoundTrip(t *testing.T) {
	secret := []byte("gateway-signing-secret")
	now := time.Unix(1_700_000_000, 0)
	exp := now.Add(5 * time.Minute).Unix()

	sig := SignClaims(secret, "7", "42", "alice", "platform:admin", exp)

	md := grpcMD.MD{}
	md.Set(MDTenantID, "7")
	md.Set(MDUserID, "42")
	md.Set(MDUsername, "alice")
	md.Set(MDRoles, "platform:admin")
	md.Set(MDClaimsSig, sig)
	md.Set(MDClaimsExp, "1700000300")

	if !VerifyClaimsSignature(md, secret, now) {
		t.Fatal("valid signature should verify")
	}
}

func TestVerifyRejectsTamperedAndForged(t *testing.T) {
	secret := []byte("gateway-signing-secret")
	now := time.Unix(1_700_000_000, 0)
	exp := int64(1_700_000_300)
	sig := SignClaims(secret, "7", "42", "alice", "user", exp)

	base := func() grpcMD.MD {
		md := grpcMD.MD{}
		md.Set(MDTenantID, "7")
		md.Set(MDUserID, "42")
		md.Set(MDUsername, "alice")
		md.Set(MDRoles, "user")
		md.Set(MDClaimsSig, sig)
		md.Set(MDClaimsExp, "1700000300")
		return md
	}

	t.Run("escalated role rejected", func(t *testing.T) {
		md := base()
		md.Set(MDRoles, "platform:admin") // attacker escalates a signed claim
		if VerifyClaimsSignature(md, secret, now) {
			t.Fatal("tampered roles must not verify")
		}
	})

	t.Run("swapped tenant rejected", func(t *testing.T) {
		md := base()
		md.Set(MDTenantID, "9") // cross-tenant swap
		if VerifyClaimsSignature(md, secret, now) {
			t.Fatal("tampered tenant must not verify")
		}
	})

	t.Run("wrong secret rejected", func(t *testing.T) {
		if VerifyClaimsSignature(base(), []byte("attacker-secret"), now) {
			t.Fatal("signature under a different secret must not verify")
		}
	})

	t.Run("empty secret rejected", func(t *testing.T) {
		if VerifyClaimsSignature(base(), nil, now) {
			t.Fatal("empty secret must fail closed")
		}
	})

	t.Run("missing signature rejected", func(t *testing.T) {
		md := base()
		md.Delete(MDClaimsSig)
		if VerifyClaimsSignature(md, secret, now) {
			t.Fatal("absent signature must not verify")
		}
	})

	t.Run("expired rejected", func(t *testing.T) {
		later := time.Unix(exp+1, 0)
		if VerifyClaimsSignature(base(), secret, later) {
			t.Fatal("expired assertion must not verify")
		}
	})
}

func TestHasUserClaimsAndStrip(t *testing.T) {
	md := grpcMD.MD{}
	if HasUserClaims(md) {
		t.Fatal("empty metadata has no user claims")
	}
	md.Set(MDRoles, "platform:admin")
	if !HasUserClaims(md) {
		t.Fatal("roles present should report user claims")
	}

	ctx := grpcMD.NewIncomingContext(context.Background(), md)
	stripped := StripUserClaims(ctx)
	if IsPlatformAdmin(stripped) {
		t.Fatal("stripped context must not report platform admin")
	}
	got, _ := grpcMD.FromIncomingContext(stripped)
	if len(got.Get(MDRoles)) != 0 {
		t.Fatal("roles must be removed after strip")
	}
}
