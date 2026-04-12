package discovery

// Standard Kubernetes labels and annotations for tangra module discovery.
const (
	// LabelModuleEnabled marks a Pod as a tangra module eligible for discovery.
	LabelModuleEnabled = "tangra.io/module"

	// LabelModuleID is the unique module identifier (e.g., "ipam", "warden").
	LabelModuleID = "tangra.io/module-id"

	// LabelModuleVersion is the module version.
	LabelModuleVersion = "tangra.io/module-version"

	// AnnotationModuleName is the human-readable module name.
	AnnotationModuleName = "tangra.io/module-name"

	// AnnotationModuleDescription is the module description.
	AnnotationModuleDescription = "tangra.io/module-description"

	// AnnotationGRPCPort is the gRPC port number.
	AnnotationGRPCPort = "tangra.io/grpc-port"

	// AnnotationHTTPPort is the HTTP port for frontend assets and API docs.
	AnnotationHTTPPort = "tangra.io/http-port"

	// AnnotationFrontendEntryURL is the Module Federation remoteEntry.js URL.
	AnnotationFrontendEntryURL = "tangra.io/frontend-entry-url"

	// AnnotationServerName is the TLS server name for mTLS.
	AnnotationServerName = "tangra.io/server-name"
)

// ModuleMetadata holds the metadata a module advertises via Pod labels/annotations.
type ModuleMetadata struct {
	ModuleID         string
	ModuleName       string
	Version          string
	Description      string
	GRPCPort         string
	HTTPPort         string
	FrontendEntryURL string
	ServerName       string
}

// Labels returns the Kubernetes labels for this module.
func (m ModuleMetadata) Labels() map[string]string {
	return map[string]string{
		LabelModuleEnabled: "true",
		LabelModuleID:      m.ModuleID,
		LabelModuleVersion: m.Version,
	}
}

// Annotations returns the Kubernetes annotations for this module.
func (m ModuleMetadata) Annotations() map[string]string {
	return map[string]string{
		AnnotationModuleName:       m.ModuleName,
		AnnotationModuleDescription: m.Description,
		AnnotationGRPCPort:         m.GRPCPort,
		AnnotationHTTPPort:         m.HTTPPort,
		AnnotationFrontendEntryURL: m.FrontendEntryURL,
		AnnotationServerName:       m.ServerName,
	}
}
