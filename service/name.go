package service

// Service name naming rules
//
// Consul：letters, numbers, dashes;
// Etcd:
// Nacos:

const (
	Project = "gotangra"

	AdminService = "admin-gateway" // Backstage BFF
)

// NewDiscoveryName constructs the service discovery name
func NewDiscoveryName(serviceName string) string {
	return Project + "/" + serviceName
}
