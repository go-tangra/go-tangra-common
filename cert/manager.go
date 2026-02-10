package cert

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"

	"github.com/go-kratos/kratos/v2/log"
	"github.com/tx7do/kratos-bootstrap/bootstrap"
)

// CertManager manages TLS certificates for a service module
type CertManager struct {
	caCertPath     string
	serverCertPath string
	serverKeyPath  string
	log            *log.Helper
}

// NewCertManager creates a new certificate manager parameterized by env var prefix.
// It reads {PREFIX}_CA_CERT_PATH, {PREFIX}_SERVER_CERT_PATH, {PREFIX}_SERVER_KEY_PATH
// and falls back to /app/certs/ca/ca.crt, /app/certs/server/server.{crt,key}.
func NewCertManager(ctx *bootstrap.Context, envPrefix string) (*CertManager, error) {
	logModule := fmt.Sprintf("%s/cert", envPrefix)
	l := ctx.NewLoggerHelper(logModule)

	caCertPath := os.Getenv(envPrefix + "_CA_CERT_PATH")
	if caCertPath == "" {
		caCertPath = "/app/certs/ca/ca.crt"
	}
	serverCertPath := os.Getenv(envPrefix + "_SERVER_CERT_PATH")
	if serverCertPath == "" {
		serverCertPath = "/app/certs/server/server.crt"
	}
	serverKeyPath := os.Getenv(envPrefix + "_SERVER_KEY_PATH")
	if serverKeyPath == "" {
		serverKeyPath = "/app/certs/server/server.key"
	}

	cm := &CertManager{
		caCertPath:     caCertPath,
		serverCertPath: serverCertPath,
		serverKeyPath:  serverKeyPath,
		log:            l,
	}

	if err := cm.validateCertFiles(); err != nil {
		l.Warnf("Certificate validation warning: %v", err)
	}

	l.Infof("CertManager initialized with CA=%s, Cert=%s", caCertPath, serverCertPath)
	return cm, nil
}

// validateCertFiles checks if the required certificate files exist
func (cm *CertManager) validateCertFiles() error {
	files := []string{cm.caCertPath, cm.serverCertPath, cm.serverKeyPath}
	for _, f := range files {
		if _, err := os.Stat(f); os.IsNotExist(err) {
			return fmt.Errorf("certificate file not found: %s", f)
		}
	}
	return nil
}

// GetServerTLSConfig returns a TLS configuration for the server with mTLS
func (cm *CertManager) GetServerTLSConfig() (*tls.Config, error) {
	caCert, err := os.ReadFile(cm.caCertPath)
	if err != nil {
		cm.log.Errorf("Failed to read CA cert: %v", err)
		return nil, fmt.Errorf("failed to read CA certificate: %w", err)
	}

	caCertPool := x509.NewCertPool()
	if !caCertPool.AppendCertsFromPEM(caCert) {
		cm.log.Error("Failed to parse CA certificate")
		return nil, fmt.Errorf("failed to parse CA certificate")
	}

	serverCert, err := tls.LoadX509KeyPair(cm.serverCertPath, cm.serverKeyPath)
	if err != nil {
		cm.log.Errorf("Failed to load server cert/key: %v", err)
		return nil, fmt.Errorf("failed to load server certificate: %w", err)
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		ClientCAs:    caCertPool,
		ClientAuth:   tls.RequireAndVerifyClientCert,
		MinVersion:   tls.VersionTLS12,
	}

	cm.log.Info("Server TLS config created with mTLS enabled")
	return tlsConfig, nil
}

// IsTLSEnabled checks if TLS certificates are available
func (cm *CertManager) IsTLSEnabled() bool {
	return cm.validateCertFiles() == nil
}
