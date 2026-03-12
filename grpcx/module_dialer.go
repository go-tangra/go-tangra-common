package grpcx

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

// ModuleDialer resolves module endpoints via admin-service and creates mTLS gRPC connections.
// It uses convention-based cert paths:
//
//	CA:     {certsDir}/ca/ca.crt
//	Client: {certsDir}/{callerModuleID}/{callerModuleID}.crt
//	Key:    {certsDir}/{callerModuleID}/{callerModuleID}.key
type ModuleDialer struct {
	adminConn      *grpc.ClientConn
	regClient      commonV1.ModuleRegistrationServiceClient
	callerModuleID string
	certsDir       string
	log            *log.Helper
}

// NewModuleDialer creates a dialer that resolves modules via admin-service.
// callerModuleID identifies this module (used for client cert path convention).
// adminConn is the existing gRPC connection to admin-service (registration conn).
// certsDir is the base directory for certificates (default: /app/certs).
func NewModuleDialer(logger log.Logger, callerModuleID string, adminConn *grpc.ClientConn, certsDir string) *ModuleDialer {
	if certsDir == "" {
		certsDir = "/app/certs"
	}
	return &ModuleDialer{
		adminConn:      adminConn,
		regClient:      commonV1.NewModuleRegistrationServiceClient(adminConn),
		callerModuleID: callerModuleID,
		certsDir:       certsDir,
		log:            log.NewHelper(log.With(logger, "module", "grpcx/dialer")),
	}
}

// DialModule resolves a target module via admin-service and returns a mTLS gRPC connection.
// It retries resolution up to maxRetries times with retryInterval between attempts.
func (d *ModuleDialer) DialModule(ctx context.Context, targetModuleID string, maxRetries int, retryInterval time.Duration) (*grpc.ClientConn, error) {
	var lastErr error

	for attempt := 0; attempt <= maxRetries; attempt++ {
		if attempt > 0 {
			d.log.Infof("Retrying module resolution for %s (attempt %d/%d)", targetModuleID, attempt+1, maxRetries+1)
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(retryInterval):
			}
		}

		resp, err := d.regClient.ResolveModule(ctx, &commonV1.ResolveModuleRequest{
			ModuleId: targetModuleID,
		})
		if err != nil {
			lastErr = fmt.Errorf("ResolveModule(%s) failed: %w", targetModuleID, err)
			d.log.Warnf("%v", lastErr)
			continue
		}

		conn, err := d.dialWithMTLS(resp.GetGrpcEndpoint(), resp.GetServerName())
		if err != nil {
			lastErr = fmt.Errorf("dial %s at %s failed: %w", targetModuleID, resp.GetGrpcEndpoint(), err)
			d.log.Warnf("%v", lastErr)
			continue
		}

		d.log.Infof("Connected to module %s at %s (server_name=%s)", targetModuleID, resp.GetGrpcEndpoint(), resp.GetServerName())
		return conn, nil
	}

	return nil, fmt.Errorf("failed to connect to module %s after %d attempts: %w", targetModuleID, maxRetries+1, lastErr)
}

// dialWithMTLS creates a gRPC connection using convention-based mTLS cert paths.
func (d *ModuleDialer) dialWithMTLS(endpoint, serverName string) (*grpc.ClientConn, error) {
	transportCreds, err := d.loadClientTLS(serverName)
	if err != nil {
		d.log.Warnf("Failed to load mTLS creds for %s, using insecure: %v", serverName, err)
		transportCreds = nil
	}

	var dialOpt grpc.DialOption
	if transportCreds != nil {
		dialOpt = grpc.WithTransportCredentials(transportCreds)
	} else {
		dialOpt = grpc.WithTransportCredentials(insecure.NewCredentials())
	}

	conn, err := grpc.NewClient(
		endpoint,
		dialOpt,
		grpc.WithConnectParams(grpc.ConnectParams{
			Backoff: backoff.Config{
				BaseDelay:  1 * time.Second,
				Multiplier: 1.5,
				Jitter:     0.2,
				MaxDelay:   30 * time.Second,
			},
			MinConnectTimeout: 5 * time.Second,
		}),
		grpc.WithKeepaliveParams(keepalive.ClientParameters{
			Time:                5 * time.Minute,
			Timeout:             20 * time.Second,
			PermitWithoutStream: false,
		}),
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
		return nil, fmt.Errorf("grpc.NewClient(%s) failed: %w", endpoint, err)
	}

	return conn, nil
}

// loadClientTLS loads mTLS credentials using convention-based paths:
//
//	CA:  {certsDir}/ca/ca.crt
//	Cert: {certsDir}/{callerModuleID}/{callerModuleID}.crt
//	Key:  {certsDir}/{callerModuleID}/{callerModuleID}.key
func (d *ModuleDialer) loadClientTLS(serverName string) (credentials.TransportCredentials, error) {
	caCertPath := filepath.Join(d.certsDir, "ca", "ca.crt")
	clientCertPath := filepath.Join(d.certsDir, d.callerModuleID, d.callerModuleID+".crt")
	clientKeyPath := filepath.Join(d.certsDir, d.callerModuleID, d.callerModuleID+".key")

	caCert, err := os.ReadFile(caCertPath)
	if err != nil {
		return nil, fmt.Errorf("read CA cert %s: %w", caCertPath, err)
	}

	caCertPool := x509.NewCertPool()
	if !caCertPool.AppendCertsFromPEM(caCert) {
		return nil, fmt.Errorf("parse CA cert from %s", caCertPath)
	}

	clientCert, err := tls.LoadX509KeyPair(clientCertPath, clientKeyPath)
	if err != nil {
		return nil, fmt.Errorf("load client cert %s: %w", clientCertPath, err)
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{clientCert},
		RootCAs:      caCertPool,
		ServerName:   serverName,
		MinVersion:   tls.VersionTLS12,
	}

	return credentials.NewTLS(tlsConfig), nil
}
