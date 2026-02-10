package cert

import (
	"context"
	"crypto/tls"
	"fmt"
	"os"
	"path/filepath"

	"github.com/go-kratos/kratos/v2/log"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	commonV1 "github.com/go-tangra/go-tangra-common/gen/go/common/service/v1"
)

// BootstrapConfig holds configuration for self-service certificate bootstrapping
type BootstrapConfig struct {
	ModuleID      string   // e.g. "deployer"
	LCMEndpoint   string   // e.g. "lcm-server:9100"
	Secret        string   // module_registration_secret
	CertOutputDir string   // where to write certs (e.g. "/app/certs")
	DNSNames      []string // SANs for server cert
	IPAddresses   []string
}

// BootstrapCertificates connects to LCM and requests certificates for this module.
// It writes CA cert, client cert+key, and server cert+key to CertOutputDir.
func BootstrapCertificates(ctx context.Context, cfg *BootstrapConfig, logger log.Logger) error {
	l := log.NewHelper(log.With(logger, "module", "cert/bootstrap"))

	l.Infof("Bootstrapping certificates for module %s from %s", cfg.ModuleID, cfg.LCMEndpoint)

	// Connect with TLS skip-verify since we don't have the CA cert yet
	tlsConfig := &tls.Config{InsecureSkipVerify: true} //nolint:gosec // needed for initial bootstrap
	conn, err := grpc.NewClient(
		cfg.LCMEndpoint,
		grpc.WithTransportCredentials(credentials.NewTLS(tlsConfig)),
	)
	if err != nil {
		return fmt.Errorf("failed to connect to LCM: %w", err)
	}
	defer conn.Close()

	client := commonV1.NewLcmBootstrapServiceClient(conn)

	resp, err := client.BootstrapCertificates(ctx, &commonV1.BootstrapCertificatesRequest{
		ModuleId:    cfg.ModuleID,
		Secret:      cfg.Secret,
		DnsNames:    cfg.DNSNames,
		IpAddresses: cfg.IPAddresses,
	})
	if err != nil {
		return fmt.Errorf("BootstrapCertificates RPC failed: %w", err)
	}

	// Write CA certificate
	caDir := filepath.Join(cfg.CertOutputDir, "ca")
	if err := os.MkdirAll(caDir, 0755); err != nil {
		return fmt.Errorf("failed to create CA dir: %w", err)
	}
	if err := os.WriteFile(filepath.Join(caDir, "ca.crt"), []byte(resp.GetCaCertificatePem()), 0644); err != nil {
		return fmt.Errorf("failed to write CA cert: %w", err)
	}

	// Write client certificate and key
	clientDir := filepath.Join(cfg.CertOutputDir, "client")
	if err := os.MkdirAll(clientDir, 0755); err != nil {
		return fmt.Errorf("failed to create client dir: %w", err)
	}
	if err := os.WriteFile(filepath.Join(clientDir, "client.crt"), []byte(resp.GetClientCertificatePem()), 0644); err != nil {
		return fmt.Errorf("failed to write client cert: %w", err)
	}
	if err := os.WriteFile(filepath.Join(clientDir, "client.key"), []byte(resp.GetClientKeyPem()), 0600); err != nil {
		return fmt.Errorf("failed to write client key: %w", err)
	}

	// Write server certificate and key
	serverDir := filepath.Join(cfg.CertOutputDir, "server")
	if err := os.MkdirAll(serverDir, 0755); err != nil {
		return fmt.Errorf("failed to create server dir: %w", err)
	}
	if err := os.WriteFile(filepath.Join(serverDir, "server.crt"), []byte(resp.GetServerCertificatePem()), 0644); err != nil {
		return fmt.Errorf("failed to write server cert: %w", err)
	}
	if err := os.WriteFile(filepath.Join(serverDir, "server.key"), []byte(resp.GetServerKeyPem()), 0600); err != nil {
		return fmt.Errorf("failed to write server key: %w", err)
	}

	l.Infof("Certificates bootstrapped successfully for module %s: %s", cfg.ModuleID, resp.GetMessage())
	return nil
}
