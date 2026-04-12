// Package discovery provides automatic service discovery for tangra modules.
// In Kubernetes, modules register via Pod labels/annotations and discover
// each other through the K8s API. In Docker/standalone mode, modules fall
// back to the existing gRPC registration with the admin gateway.
package discovery

import "os"

// Environment describes the runtime environment.
type Environment int

const (
	EnvDocker     Environment = iota // Docker Compose or standalone
	EnvKubernetes                    // Kubernetes cluster
)

// Detect returns the current runtime environment.
func Detect() Environment {
	if os.Getenv("KUBERNETES_SERVICE_HOST") != "" {
		return EnvKubernetes
	}
	return EnvDocker
}

// IsKubernetes returns true if running inside a Kubernetes cluster.
func IsKubernetes() bool {
	return Detect() == EnvKubernetes
}
