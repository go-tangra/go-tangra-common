package registration

import (
	"context"
	"os"
	"time"

	"github.com/go-kratos/kratos/v2/log"
	"github.com/tx7do/kratos-bootstrap/bootstrap"
)

// RegistrationHelper manages the module registration lifecycle with the admin gateway.
type RegistrationHelper struct {
	client *Client
	logger *log.Helper
}

// StartRegistration begins the module registration lifecycle in a background goroutine.
// If ADMIN_GRPC_ENDPOINT is not set, registration is skipped and a no-op helper is returned.
func StartRegistration(ctx *bootstrap.Context, logger log.Logger, cfg *Config) *RegistrationHelper {
	h := &RegistrationHelper{
		logger: log.NewHelper(log.With(logger, "module", "registration/lifecycle")),
	}

	adminEndpoint := cfg.AdminEndpoint
	if adminEndpoint == "" {
		h.logger.Info("ADMIN_GRPC_ENDPOINT not set, skipping module registration")
		return h
	}

	h.logger.Infof("Will register with admin gateway at: %s", adminEndpoint)

	// Start registration in background after a delay
	go func() {
		// Wait for gRPC server to be ready
		time.Sleep(3 * time.Second)

		regClient, err := NewClient(logger, cfg)
		if err != nil {
			h.logger.Warnf("Failed to create registration client: %v", err)
			return
		}
		h.client = regClient

		// Register with admin gateway
		regCtx := context.Background()
		if err := regClient.Register(regCtx); err != nil {
			h.logger.Errorf("Failed to register with admin gateway: %v", err)
			return
		}

		// Start heartbeat
		go regClient.StartHeartbeat(regCtx)
	}()

	return h
}

// StartRegistrationWithClient begins the registration lifecycle using a pre-created Client.
// Use this when the Client was created earlier (e.g. during Wire DI for ModuleDialer).
func StartRegistrationWithClient(logger log.Logger, client *Client) *RegistrationHelper {
	h := &RegistrationHelper{
		client: client,
		logger: log.NewHelper(log.With(logger, "module", "registration/lifecycle")),
	}

	go func() {
		time.Sleep(3 * time.Second)

		regCtx := context.Background()
		if err := client.Register(regCtx); err != nil {
			h.logger.Errorf("Failed to register with admin gateway: %v", err)
			return
		}

		go client.StartHeartbeat(regCtx)
	}()

	return h
}

// Stop unregisters from admin gateway and closes the connection.
func (h *RegistrationHelper) Stop() {
	if h == nil || h.client == nil {
		return
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := h.client.Unregister(shutdownCtx); err != nil {
		h.logger.Warnf("Failed to unregister from admin gateway: %v", err)
	}
	_ = h.client.Close()
}

// GetEnvOrDefault returns the value of the environment variable key,
// or defaultValue if the variable is not set or empty.
func GetEnvOrDefault(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

// GetGRPCAdvertiseAddr returns the gRPC advertise address from the GRPC_ADVERTISE_ADDR
// environment variable, falling back to the bootstrap config address or defaultAddr.
func GetGRPCAdvertiseAddr(ctx *bootstrap.Context, defaultAddr string) string {
	grpcAddr := GetEnvOrDefault("GRPC_ADVERTISE_ADDR", "")
	if grpcAddr != "" {
		return grpcAddr
	}

	cfg := ctx.GetConfig()
	if cfg.Server != nil && cfg.Server.Grpc != nil && cfg.Server.Grpc.Addr != "" {
		return cfg.Server.Grpc.Addr
	}

	return defaultAddr
}
