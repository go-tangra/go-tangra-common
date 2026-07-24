package mtls

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"testing"

	"github.com/go-kratos/kratos/v2/log"
)

func certWithCN(cn string) *x509.Certificate {
	return &x509.Certificate{Subject: pkix.Name{CommonName: cn}}
}

func TestValidateCertificateIdentity(t *testing.T) {
	l := log.NewHelper(log.DefaultLogger)

	tests := []struct {
		name    string
		allowed []string
		mode    string
		cn      string
		wantErr bool
	}{
		{
			name:    "no allow-list configured is a no-op",
			allowed: nil,
			mode:    IdentityModeEnforce,
			cn:      "lcm-attacker",
			wantErr: false,
		},
		{
			name:    "mode off bypasses the allow-list",
			allowed: []string{"lcm-portal"},
			mode:    IdentityModeOff,
			cn:      "lcm-attacker",
			wantErr: false,
		},
		{
			name:    "enforce rejects a CN not in the allow-list",
			allowed: []string{"lcm-portal"},
			mode:    IdentityModeEnforce,
			cn:      "lcm-attacker",
			wantErr: true,
		},
		{
			name:    "enforce accepts a listed CN",
			allowed: []string{"lcm-portal", "lcm-backup"},
			mode:    IdentityModeEnforce,
			cn:      "lcm-backup",
			wantErr: false,
		},
		{
			name:    "warn accepts an unlisted CN",
			allowed: []string{"lcm-portal"},
			mode:    IdentityModeWarn,
			cn:      "lcm-attacker",
			wantErr: false,
		},
		{
			name:    "enforce rejects an empty CN when a list is set",
			allowed: []string{"lcm-portal"},
			mode:    IdentityModeEnforce,
			cn:      "",
			wantErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			opts := &Options{AllowedCommonNames: tc.allowed, IdentityMode: tc.mode}
			err := validateCertificateIdentity(certWithCN(tc.cn), opts, l)
			if (err != nil) != tc.wantErr {
				t.Fatalf("validateCertificateIdentity(cn=%q, mode=%q) err = %v, wantErr = %v",
					tc.cn, tc.mode, err, tc.wantErr)
			}
		})
	}
}
