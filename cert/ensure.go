package cert

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/go-kratos/kratos/v2/log"

	commonV1 "github.com/go-tangra/go-tangra-common/gen/go/common/service/v1"
)

// EnsureConfig drives Ensure(). Most callers only need to set
// ModuleID + Logger; the rest reads from environment variables that
// every tangra module already has, so adding cert.Ensure to a module
// is a single function call.
type EnsureConfig struct {
	// ModuleID is the canonical short name of the module (e.g.
	// "sms-gw"). Used as the CN on the issued cert and as the rate-
	// limit bucket key on LCM.
	ModuleID string

	// LCMEndpoint is the lcm-service bootstrap port (default: env
	// LCM_BOOTSTRAP_ENDPOINT, e.g. "lcm-service:9101").
	LCMEndpoint string

	// Secret is the shared MODULE_BOOTSTRAP_SECRET. Falls back to env.
	Secret string

	// CertsDir is where {ca,client,server} subdirs are written.
	// Defaults to env CERTS_DIR or "/app/certs".
	CertsDir string

	// PinnedCAFingerprint is the SHA-256 hex of the LCM root CA's
	// DER bytes. REQUIRED. Defaults to env LCM_CA_FINGERPRINT.
	// We deliberately do not support TOFU — a missing fingerprint is
	// a fatal config error, not a free pass.
	PinnedCAFingerprint string

	// DNSNames + IPAddresses are SANs on the issued server cert.
	// Defaults to {ModuleID + "-service"} for DNS and the host's
	// non-loopback v4/v6 addresses for IP. Loopback is always added
	// by LCM regardless of input.
	DNSNames    []string
	IPAddresses []string

	// RenewBefore controls how far ahead of NotAfter we re-issue.
	// Default: 30 days. The default is generous on purpose — a
	// stuck renewal still has a month to recover before TLS breaks.
	RenewBefore time.Duration

	// Logger is the kratos logger this package writes to.
	Logger log.Logger
}

// Ensure makes the local cert directory match the contract:
// CA + server cert + key, all valid, signed by the pinned LCM, with
// at least RenewBefore lifetime remaining.
//
// On every boot:
//  1. Resolve config defaults from env.
//  2. Run CheckLocalCert. If OK → load and return.
//  3. Otherwise: dial LCM (pinned-fingerprint TLS, no client cert),
//     generate a key + CSR locally, send SignModuleCertificate, write
//     the response to disk in the {ca, client, server} layout the rest
//     of the system already reads, return a fresh CertManager.
//
// Both server and client certs are issued in this call (two RPCs back
// to back) so a single Ensure() leaves the module fully provisioned
// for both inbound mTLS and outbound mTLS dials.
func Ensure(ctx context.Context, cfg EnsureConfig) (*CertManager, error) {
	if err := applyDefaults(&cfg); err != nil {
		return nil, err
	}
	l := log.NewHelper(log.With(cfg.Logger, "module", "cert/ensure"))

	health := CheckLocalCert(cfg.CertsDir, cfg.PinnedCAFingerprint, cfg.RenewBefore)
	if health.OK {
		l.Infof("local cert OK (notAfter=%s, fingerprint=%s)",
			health.Cert.NotAfter, FingerprintSHA256(health.CA))
		return loadManager(cfg, l)
	}

	l.Infof("re-issuing certs for %s: %s", cfg.ModuleID, health.Reason)

	conn, err := PinnedDial(cfg.LCMEndpoint, cfg.PinnedCAFingerprint)
	if err != nil {
		return nil, fmt.Errorf("dial lcm: %w", err)
	}
	defer func() { _ = conn.Close() }()

	client := commonV1.NewLcmBootstrapServiceClient(conn)

	if err := signAndPersist(ctx, client, cfg, commonV1.CertificateKind_CERT_KIND_SERVER, "server", cfg.ModuleID+"-service"); err != nil {
		return nil, fmt.Errorf("server cert: %w", err)
	}
	if err := signAndPersist(ctx, client, cfg, commonV1.CertificateKind_CERT_KIND_CLIENT, "client", "lcm-"+cfg.ModuleID); err != nil {
		return nil, fmt.Errorf("client cert: %w", err)
	}

	l.Infof("certs provisioned for %s in %s", cfg.ModuleID, cfg.CertsDir)
	return loadManager(cfg, l)
}

// signAndPersist runs one CSR cycle: keygen → SignModuleCertificate →
// write the {kind}.crt + {kind}.key + ca/ca.crt + ca.fingerprint to
// disk. Both kinds end up writing the same ca.crt — the second pass
// is a no-op overwrite, simpler than threading a "skip CA" flag.
func signAndPersist(
	ctx context.Context,
	client commonV1.LcmBootstrapServiceClient,
	cfg EnsureConfig,
	kind commonV1.CertificateKind,
	subdir string,
	commonName string,
) error {
	key, csrPEM, err := GenerateKeyAndCSR(commonName, cfg.DNSNames, cfg.IPAddresses)
	if err != nil {
		return err
	}
	resp, err := client.SignModuleCertificate(ctx, &commonV1.SignModuleCertificateRequest{
		ModuleId: cfg.ModuleID,
		Secret:   cfg.Secret,
		CsrPem:   string(csrPEM),
		Kind:     kind,
	})
	if err != nil {
		return fmt.Errorf("SignModuleCertificate: %w", err)
	}
	// Belt-and-braces: verify the CA bundle the server returned still
	// matches the pinned fingerprint we used to dial. A mismatch here
	// would mean the server is using a different CA than its own
	// presented chain — a misconfiguration we want to fail loudly on
	// rather than silently writing the wrong CA to disk.
	if !strings.EqualFold(resp.GetCaFingerprintSha256(), cfg.PinnedCAFingerprint) {
		return fmt.Errorf(
			"CA fingerprint in response (%s) does not match pinned (%s)",
			resp.GetCaFingerprintSha256(), cfg.PinnedCAFingerprint,
		)
	}

	keyPEM, err := MarshalKeyPEM(key)
	if err != nil {
		return err
	}

	if err := writeFile(filepath.Join(cfg.CertsDir, "ca", "ca.crt"), []byte(resp.GetCaCertificatePem()), 0o644); err != nil {
		return err
	}
	if err := writeFile(filepath.Join(cfg.CertsDir, subdir, subdir+".crt"), []byte(resp.GetCertificatePem()), 0o644); err != nil {
		return err
	}
	if err := writeFile(filepath.Join(cfg.CertsDir, subdir, subdir+".key"), keyPEM, 0o600); err != nil {
		return err
	}
	return nil
}

// loadManager constructs the CertManager the rest of the module
// already consumes. Its envPrefix-based file lookup is overridden by
// CERTS_DIR being set — the standard layout below means
// {CERTS_DIR}/server/server.{crt,key} is what NewCertManager reads.
func loadManager(cfg EnsureConfig, l *log.Helper) (*CertManager, error) {
	cm := &CertManager{
		caCertPath:     filepath.Join(cfg.CertsDir, "ca", "ca.crt"),
		serverCertPath: filepath.Join(cfg.CertsDir, "server", "server.crt"),
		serverKeyPath:  filepath.Join(cfg.CertsDir, "server", "server.key"),
		log:            l,
	}
	if err := cm.validateCertFiles(); err != nil {
		return nil, fmt.Errorf("post-bootstrap validation: %w", err)
	}
	return cm, nil
}

func writeFile(path string, data []byte, mode os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("mkdir %s: %w", filepath.Dir(path), err)
	}
	if err := os.WriteFile(path, data, mode); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	return nil
}

func applyDefaults(cfg *EnsureConfig) error {
	if cfg.ModuleID == "" {
		return fmt.Errorf("ModuleID is required")
	}
	if cfg.Logger == nil {
		return fmt.Errorf("Logger is required")
	}
	if cfg.LCMEndpoint == "" {
		cfg.LCMEndpoint = os.Getenv("LCM_BOOTSTRAP_ENDPOINT")
		if cfg.LCMEndpoint == "" {
			return fmt.Errorf("LCMEndpoint not set (env LCM_BOOTSTRAP_ENDPOINT)")
		}
	}
	if cfg.Secret == "" {
		cfg.Secret = os.Getenv("MODULE_BOOTSTRAP_SECRET")
		if cfg.Secret == "" {
			return fmt.Errorf("Secret not set (env MODULE_BOOTSTRAP_SECRET)")
		}
	}
	if cfg.CertsDir == "" {
		cfg.CertsDir = os.Getenv("CERTS_DIR")
		if cfg.CertsDir == "" {
			cfg.CertsDir = "/app/certs"
		}
	}
	if cfg.PinnedCAFingerprint == "" {
		cfg.PinnedCAFingerprint = os.Getenv("LCM_CA_FINGERPRINT")
		if cfg.PinnedCAFingerprint == "" {
			return fmt.Errorf("PinnedCAFingerprint not set (env LCM_CA_FINGERPRINT) — pinning is mandatory")
		}
	}
	if len(cfg.DNSNames) == 0 {
		cfg.DNSNames = []string{cfg.ModuleID + "-service"}
	}
	if len(cfg.IPAddresses) == 0 {
		cfg.IPAddresses = detectLocalIPs()
	}
	if cfg.RenewBefore <= 0 {
		cfg.RenewBefore = 30 * 24 * time.Hour
	}
	return nil
}

// detectLocalIPs collects every routable v4/v6 the host advertises on
// any non-loopback interface. Best-effort: errors are silently ignored
// and an empty list returned — LCM always adds 127.0.0.1 + ::1
// regardless, so a module that can't enumerate interfaces still gets
// a usable cert.
func detectLocalIPs() []string {
	out := []string{}
	ifaces, err := net.Interfaces()
	if err != nil {
		return out
	}
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			var ip net.IP
			switch v := a.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}
			if ip == nil || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
				continue
			}
			out = append(out, ip.String())
		}
	}
	return out
}
