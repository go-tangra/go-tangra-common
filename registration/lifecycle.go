package registration

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/go-kratos/kratos/v2/log"
	"github.com/tx7do/kratos-bootstrap/bootstrap"

	"github.com/go-tangra/go-tangra-common/discovery"
)

// RegistrationHelper manages the module registration lifecycle with the admin gateway.
// In Kubernetes, it patches the Pod with discovery labels/annotations instead of
// using gRPC registration. In Docker, it uses the existing gRPC push model.
type RegistrationHelper struct {
	client       *Client
	k8sRegistrar *discovery.K8sRegistrar
	logger       *log.Helper
}

// StartRegistration begins the module registration lifecycle in a background goroutine.
// It auto-detects Kubernetes vs Docker:
//   - Kubernetes: patches Pod labels/annotations for automatic discovery
//   - Docker: registers via gRPC with the admin gateway
func StartRegistration(ctx *bootstrap.Context, logger log.Logger, cfg *Config) *RegistrationHelper {
	h := &RegistrationHelper{
		logger: log.NewHelper(log.With(logger, "module", "registration/lifecycle")),
	}

	if discovery.IsKubernetes() {
		h.startK8sRegistration(logger, cfg)
		return h
	}

	// Docker mode: use existing gRPC registration
	adminEndpoint := cfg.AdminEndpoint
	if adminEndpoint == "" {
		h.logger.Info("ADMIN_GRPC_ENDPOINT not set, skipping module registration")
		return h
	}

	h.logger.Infof("Docker mode: will register with admin gateway at: %s", adminEndpoint)
	h.startGRPCRegistration(logger, cfg)
	return h
}

// startK8sRegistration patches the Pod with module labels/annotations.
func (h *RegistrationHelper) startK8sRegistration(logger log.Logger, cfg *Config) {
	h.logger.Info("Kubernetes mode: registering via Pod labels/annotations")

	go func() {
		time.Sleep(3 * time.Second)

		registrar, err := discovery.NewK8sRegistrar(logger)
		if err != nil {
			h.logger.Errorf("Failed to create K8s registrar: %v", err)
			// Fall back to gRPC registration
			h.logger.Info("Falling back to gRPC registration")
			h.startGRPCRegistration(logger, cfg)
			return
		}
		h.k8sRegistrar = registrar

		grpcPort := ""
		if cfg.GRPCEndpoint != "" {
			// Extract port from "0.0.0.0:9400" or "ipam-service:9400"
			if idx := lastIndexByte(cfg.GRPCEndpoint, ':'); idx >= 0 {
				grpcPort = cfg.GRPCEndpoint[idx+1:]
			}
		}

		httpPort := GetEnvOrDefault("HTTP_ADVERTISE_ADDR", "")
		if httpPort != "" {
			if idx := lastIndexByte(httpPort, ':'); idx >= 0 {
				httpPort = httpPort[idx+1:]
			}
		}

		meta := discovery.ModuleMetadata{
			ModuleID:         cfg.ModuleID,
			ModuleName:       cfg.ModuleName,
			Version:          cfg.Version,
			Description:      cfg.Description,
			GRPCPort:         grpcPort,
			HTTPPort:         httpPort,
			FrontendEntryURL: GetEnvOrDefault("FRONTEND_ENTRY_URL", ""),
			ServerName:       cfg.ServerName,
		}

		if err := registrar.Register(context.Background(), meta); err != nil {
			h.logger.Errorf("K8s registration failed: %v", err)
			// Fall back to gRPC registration
			h.logger.Info("Falling back to gRPC registration")
			h.startGRPCRegistration(logger, cfg)
			return
		}

		h.logger.Infof("Module %s registered via Kubernetes (no heartbeat needed)", cfg.ModuleID)
	}()
}

// startGRPCRegistration uses the existing gRPC push model.
func (h *RegistrationHelper) startGRPCRegistration(logger log.Logger, cfg *Config) {
	go func() {
		time.Sleep(3 * time.Second)

		regClient, err := NewClient(logger, cfg)
		if err != nil {
			h.logger.Warnf("Failed to create registration client: %v", err)
			return
		}
		h.client = regClient

		regCtx := context.Background()
		if err := regClient.Register(regCtx); err != nil {
			h.logger.Errorf("Failed to register with admin gateway: %v", err)
			return
		}

		go regClient.StartHeartbeat(regCtx)
	}()
}

func lastIndexByte(s string, c byte) int {
	for i := len(s) - 1; i >= 0; i-- {
		if s[i] == c {
			return i
		}
	}
	return -1
}

// DiscoveryMode returns a string describing the discovery mode for logging.
func DiscoveryMode() string {
	if discovery.IsKubernetes() {
		return "kubernetes"
	}
	return "docker"
}

// FormatEndpoint builds an endpoint string from service name and port for K8s DNS.
func FormatEndpoint(moduleID string, port string) string {
	return fmt.Sprintf("%s-service:%s", moduleID, port)
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

// Stop unregisters from admin gateway (Docker) or removes Pod labels (K8s).
func (h *RegistrationHelper) Stop() {
	if h == nil {
		return
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if h.k8sRegistrar != nil {
		if err := h.k8sRegistrar.Unregister(shutdownCtx); err != nil {
			h.logger.Warnf("Failed to unregister from K8s: %v", err)
		}
	}

	if h.client != nil {
		if err := h.client.Unregister(shutdownCtx); err != nil {
			h.logger.Warnf("Failed to unregister from admin gateway: %v", err)
		}
		_ = h.client.Close()
	}
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
