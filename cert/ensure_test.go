package cert

import (
	"strings"
	"testing"
	"time"

	"github.com/go-kratos/kratos/v2/log"
)

func TestApplyDefaults_RequiredFields(t *testing.T) {
	cases := []struct {
		name string
		cfg  EnsureConfig
		want string // substring expected in the error
	}{
		{
			name: "missing module id",
			cfg:  EnsureConfig{Logger: log.DefaultLogger},
			want: "ModuleID",
		},
		{
			name: "missing logger",
			cfg:  EnsureConfig{ModuleID: "x"},
			want: "Logger",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := applyDefaults(&tc.cfg)
			if err == nil {
				t.Fatalf("expected error containing %q, got nil", tc.want)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("err = %q, want substring %q", err, tc.want)
			}
		})
	}
}

func TestApplyDefaults_RequiresEnvOrFields(t *testing.T) {
	// Each env var the defaults depend on is unset for this test
	// process — clearing them here makes the assertion deterministic
	// regardless of how the caller's shell is configured.
	t.Setenv("LCM_BOOTSTRAP_ENDPOINT", "")
	t.Setenv("MODULE_BOOTSTRAP_SECRET", "")
	t.Setenv("LCM_CA_FINGERPRINT", "")

	cfg := EnsureConfig{ModuleID: "x", Logger: log.DefaultLogger}
	err := applyDefaults(&cfg)
	if err == nil || !strings.Contains(err.Error(), "LCMEndpoint") {
		t.Fatalf("expected LCMEndpoint error, got: %v", err)
	}
}

func TestApplyDefaults_FillsFromEnv(t *testing.T) {
	t.Setenv("LCM_BOOTSTRAP_ENDPOINT", "lcm:9101")
	t.Setenv("MODULE_BOOTSTRAP_SECRET", "secret-from-env")
	t.Setenv("LCM_CA_FINGERPRINT", "a1b2c3")
	t.Setenv("CERTS_DIR", "/tmp/test-certs")

	cfg := EnsureConfig{ModuleID: "demo", Logger: log.DefaultLogger}
	if err := applyDefaults(&cfg); err != nil {
		t.Fatalf("applyDefaults: %v", err)
	}
	if cfg.LCMEndpoint != "lcm:9101" {
		t.Errorf("LCMEndpoint = %q", cfg.LCMEndpoint)
	}
	if cfg.Secret != "secret-from-env" {
		t.Errorf("Secret = %q", cfg.Secret)
	}
	if cfg.PinnedCAFingerprint != "a1b2c3" {
		t.Errorf("PinnedCAFingerprint = %q", cfg.PinnedCAFingerprint)
	}
	if cfg.CertsDir != "/tmp/test-certs" {
		t.Errorf("CertsDir = %q", cfg.CertsDir)
	}
	if len(cfg.DNSNames) != 1 || cfg.DNSNames[0] != "demo-service" {
		t.Errorf("default DNSNames = %v, want [demo-service]", cfg.DNSNames)
	}
	if cfg.RenewBefore != 30*24*time.Hour {
		t.Errorf("default RenewBefore = %v, want 30d", cfg.RenewBefore)
	}
}

func TestApplyDefaults_FingerprintIsMandatory(t *testing.T) {
	t.Setenv("LCM_BOOTSTRAP_ENDPOINT", "lcm:9101")
	t.Setenv("MODULE_BOOTSTRAP_SECRET", "secret")
	t.Setenv("LCM_CA_FINGERPRINT", "")

	cfg := EnsureConfig{ModuleID: "demo", Logger: log.DefaultLogger}
	err := applyDefaults(&cfg)
	if err == nil || !strings.Contains(err.Error(), "PinnedCAFingerprint") {
		t.Fatalf("expected PinnedCAFingerprint error (pinning is mandatory), got: %v", err)
	}
}

func TestDetectLocalIPs_NoCrash(t *testing.T) {
	t.Parallel()
	// Pure smoke test — the function depends on the runtime
	// environment so we can't assert exact contents, but it must
	// never panic and the entries (if any) must be valid IP strings.
	got := detectLocalIPs()
	for _, s := range got {
		if s == "" {
			t.Errorf("detectLocalIPs returned empty string")
		}
	}
}
