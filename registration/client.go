package registration

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/go-kratos/kratos/v2/log"
	"google.golang.org/grpc"
	"google.golang.org/grpc/backoff"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/keepalive"

	commonV1 "github.com/go-tangra/go-tangra-common/gen/go/common/service/v1"
)

// Config holds the registration configuration
type Config struct {
	ModuleID          string
	ModuleName        string
	Version           string
	Description       string
	GRPCEndpoint      string
	FrontendEntryUrl  string
	HttpEndpoint      string
	ServerName        string
	AdminEndpoint     string
	OpenapiSpec       []byte
	ProtoDescriptor   []byte
	MenusYaml         []byte
	AuthToken         string
	HeartbeatInterval time.Duration
	RetryInterval     time.Duration
	MaxRetries        int
}

// Client handles module registration with the admin gateway
type Client struct {
	log            *log.Helper
	config         *Config
	conn           *grpc.ClientConn
	client         commonV1.ModuleRegistrationServiceClient
	registrationID string
	stopChan       chan struct{}
}

// NewClient creates a new registration client.
// The Config.ModuleID is used in log messages to identify the module.
func NewClient(logger log.Logger, config *Config) (*Client, error) {
	logModule := fmt.Sprintf("registration/%s-service", config.ModuleID)
	l := log.NewHelper(log.With(logger, "module", logModule))

	conn, err := createConnection(config.AdminEndpoint, l)
	if err != nil {
		return nil, err
	}

	return &Client{
		log:      l,
		config:   config,
		conn:     conn,
		client:   commonV1.NewModuleRegistrationServiceClient(conn),
		stopChan: make(chan struct{}),
	}, nil
}

// Register registers this module with the admin gateway
func (c *Client) Register(ctx context.Context) error {
	c.log.Infof("Registering module %s with admin gateway at %s", c.config.ModuleID, c.config.AdminEndpoint)

	req := &commonV1.RegisterModuleRequest{
		ModuleId:         c.config.ModuleID,
		ModuleName:       c.config.ModuleName,
		Version:          c.config.Version,
		Description:      c.config.Description,
		GrpcEndpoint:     c.config.GRPCEndpoint,
		FrontendEntryUrl: c.config.FrontendEntryUrl,
		HttpEndpoint:     c.config.HttpEndpoint,
		ServerName:       c.config.ServerName,
		OpenapiSpec:      c.config.OpenapiSpec,
		ProtoDescriptor:  c.config.ProtoDescriptor,
		MenusYaml:        c.config.MenusYaml,
		AuthToken:        c.config.AuthToken,
	}

	var lastErr error
	for attempt := 0; attempt < c.config.MaxRetries; attempt++ {
		resp, err := c.client.RegisterModule(ctx, req)
		if err != nil {
			c.log.Warnf("Registration attempt %d failed: %v", attempt+1, err)
			lastErr = err
			time.Sleep(c.config.RetryInterval)
			continue
		}

		c.registrationID = resp.GetRegistrationId()
		c.log.Infof("Module registered successfully with ID: %s, status: %s",
			c.registrationID, resp.GetStatus())
		return nil
	}

	return lastErr
}

// StartHeartbeat starts the periodic heartbeat to the admin gateway
func (c *Client) StartHeartbeat(ctx context.Context) {
	ticker := time.NewTicker(c.config.HeartbeatInterval)
	defer ticker.Stop()

	c.log.Infof("Starting heartbeat with interval: %s", c.config.HeartbeatInterval)

	for {
		select {
		case <-ctx.Done():
			c.log.Info("Heartbeat stopped due to context cancellation")
			return
		case <-c.stopChan:
			c.log.Info("Heartbeat stopped")
			return
		case <-ticker.C:
			if err := c.sendHeartbeat(ctx); err != nil {
				c.log.Warnf("Heartbeat failed: %v", err)
			}
		}
	}
}

// sendHeartbeat sends a single heartbeat to the admin gateway
func (c *Client) sendHeartbeat(ctx context.Context) error {
	msg := fmt.Sprintf("%s service is healthy", c.config.ModuleName)
	req := &commonV1.HeartbeatRequest{
		ModuleId: c.config.ModuleID,
		Health:   commonV1.ModuleHealth_MODULE_HEALTH_HEALTHY,
		Message:  msg,
	}

	resp, err := c.client.Heartbeat(ctx, req)
	if err != nil {
		return err
	}

	if !resp.GetAcknowledged() {
		c.log.Warn("Heartbeat was not acknowledged by admin gateway")
	}

	return nil
}

// Unregister unregisters this module from the admin gateway
func (c *Client) Unregister(ctx context.Context) error {
	c.log.Infof("Unregistering module %s from admin gateway", c.config.ModuleID)

	close(c.stopChan)

	req := &commonV1.UnregisterModuleRequest{
		ModuleId:  c.config.ModuleID,
		AuthToken: c.config.AuthToken,
	}

	_, err := c.client.UnregisterModule(ctx, req)
	if err != nil {
		c.log.Errorf("Failed to unregister module: %v", err)
		return err
	}

	c.log.Info("Module unregistered successfully")
	return nil
}

// AdminConn returns the underlying gRPC connection to admin-service.
// This can be used with ModuleDialer for module-to-module communication.
func (c *Client) AdminConn() *grpc.ClientConn {
	return c.conn
}

// SetConfig updates the registration config (module metadata, assets, etc.).
// Use this when the Client was created early with minimal config (just admin endpoint),
// and the full config is set later before calling Register().
func (c *Client) SetConfig(cfg *Config) {
	// Preserve the admin endpoint and connection settings from the original config
	cfg.AdminEndpoint = c.config.AdminEndpoint
	if cfg.HeartbeatInterval == 0 {
		cfg.HeartbeatInterval = 30 * time.Second
	}
	if cfg.RetryInterval == 0 {
		cfg.RetryInterval = 5 * time.Second
	}
	if cfg.MaxRetries == 0 {
		cfg.MaxRetries = 60
	}
	c.config = cfg
}

// Close closes the connection to the admin gateway
func (c *Client) Close() error {
	if c.conn != nil {
		return c.conn.Close()
	}
	return nil
}

// loadAdminClientTLS attempts to load mTLS credentials for connecting to admin-service.
// Uses convention paths: {CERTS_DIR}/ca/ca.crt, {CERTS_DIR}/{module}/{module}.crt
// where module is the calling module's client cert (e.g. "notification/notification.crt").
// Returns nil if cert files are not found (caller should fall back to insecure).
func loadAdminClientTLS(l *log.Helper) credentials.TransportCredentials {
	certsDir := os.Getenv("CERTS_DIR")
	if certsDir == "" {
		certsDir = "/app/certs"
	}

	caCertPath := filepath.Join(certsDir, "ca", "ca.crt")

	// Find any client cert in the certs directory.
	// Modules have their client cert at {certsDir}/{module}/{module}.crt
	// The admin client cert is at {certsDir}/admin/admin.crt
	// We look for available client certs by checking common patterns.
	clientCertPath := ""
	clientKeyPath := ""

	// Check for module-specific client certs by scanning the certs directory
	entries, err := os.ReadDir(certsDir)
	if err != nil {
		return nil
	}

	for _, entry := range entries {
		if !entry.IsDir() || entry.Name() == "ca" {
			continue
		}
		name := entry.Name()
		// Skip server cert directories (e.g. "warden-server")
		if len(name) > 7 && name[len(name)-7:] == "-server" {
			continue
		}
		certPath := filepath.Join(certsDir, name, name+".crt")
		keyPath := filepath.Join(certsDir, name, name+".key")
		if _, err := os.Stat(certPath); err == nil {
			if _, err := os.Stat(keyPath); err == nil {
				clientCertPath = certPath
				clientKeyPath = keyPath
				break
			}
		}
	}

	if clientCertPath == "" {
		return nil
	}

	// Load CA certificate
	caCert, err := os.ReadFile(caCertPath)
	if err != nil {
		return nil
	}
	caCertPool := x509.NewCertPool()
	if !caCertPool.AppendCertsFromPEM(caCert) {
		return nil
	}

	// Load client certificate
	clientCert, err := tls.LoadX509KeyPair(clientCertPath, clientKeyPath)
	if err != nil {
		return nil
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{clientCert},
		RootCAs:      caCertPool,
		ServerName:   "admin-service",
		MinVersion:   tls.VersionTLS12,
	}

	l.Infof("Registration client using mTLS (cert=%s, server=admin-service)", clientCertPath)
	return credentials.NewTLS(tlsConfig)
}

// createConnection creates a gRPC connection with retry and keepalive settings.
// Uses mTLS if client certificates are available, falls back to insecure.
func createConnection(endpoint string, l *log.Helper) (*grpc.ClientConn, error) {
	connectParams := grpc.ConnectParams{
		Backoff: backoff.Config{
			BaseDelay:  1 * time.Second,
			Multiplier: 1.5,
			Jitter:     0.2,
			MaxDelay:   30 * time.Second,
		},
		MinConnectTimeout: 10 * time.Second,
	}

	keepaliveParams := keepalive.ClientParameters{
		Time:                5 * time.Minute,
		Timeout:             20 * time.Second,
		PermitWithoutStream: false,
	}

	var transportCreds grpc.DialOption
	if tlsCreds := loadAdminClientTLS(l); tlsCreds != nil {
		transportCreds = grpc.WithTransportCredentials(tlsCreds)
	} else {
		l.Info("Registration client using insecure credentials (no mTLS certs found)")
		transportCreds = grpc.WithTransportCredentials(insecure.NewCredentials())
	}

	conn, err := grpc.NewClient(
		endpoint,
		transportCreds,
		grpc.WithConnectParams(connectParams),
		grpc.WithKeepaliveParams(keepaliveParams),
		grpc.WithDefaultServiceConfig(`{
			"loadBalancingConfig": [{"round_robin":{}}],
			"methodConfig": [{
				"name": [{"service": ""}],
				"waitForReady": true,
				"retryPolicy": {
					"MaxAttempts": 3,
					"InitialBackoff": "0.5s",
					"MaxBackoff": "5s",
					"BackoffMultiplier": 2,
					"RetryableStatusCodes": ["UNAVAILABLE", "RESOURCE_EXHAUSTED"]
				}
			}]
		}`),
	)
	if err != nil {
		return nil, err
	}

	return conn, nil
}
