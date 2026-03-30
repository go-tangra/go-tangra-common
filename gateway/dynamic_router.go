package gateway

import (
	"fmt"
	"net/http"
	"strings"
	"sync"

	"github.com/go-kratos/kratos/v2/log"

	authnEngine "github.com/tx7do/kratos-authn/engine"

	"github.com/go-tangra/go-tangra-common/gateway/transcoder"
)

// DynamicRouter handles routing for dynamically registered modules.
// It uses sync.Map for lock-free reads on the hot path.
type DynamicRouter struct {
	log           *log.Helper
	transcoder    *transcoder.Transcoder
	registry      ModuleRegistry
	authenticator authnEngine.Authenticator

	// Module handlers (module_id -> *ModuleHandler)
	handlers sync.Map

	// Configurable route prefix (default: "/admin/v1/modules/")
	routePrefix string
}

// NewDynamicRouter creates a new DynamicRouter.
func NewDynamicRouter(
	logger *log.Helper,
	tc *transcoder.Transcoder,
	registry ModuleRegistry,
	authenticator authnEngine.Authenticator,
	opts ...RouterOption,
) *DynamicRouter {
	dr := &DynamicRouter{
		log:           logger,
		transcoder:    tc,
		registry:      registry,
		authenticator: authenticator,
		routePrefix:   "/admin/v1/modules/",
	}

	for _, opt := range opts {
		opt(dr)
	}

	// Subscribe to module events for hot-reload
	registry.OnEvent(dr.handleModuleEvent)

	return dr
}

// handleModuleEvent handles module lifecycle events.
func (dr *DynamicRouter) handleModuleEvent(event ModuleEvent) {
	switch event.Type {
	case ModuleEventRegistered, ModuleEventUpdated:
		dr.registerModuleHandler(event.Module)
	case ModuleEventUnregistered:
		dr.unregisterModuleHandler(event.Module.ModuleID)
	case ModuleEventHealthChanged:
		dr.log.Infof("Module %s health changed to %s", event.Module.ModuleID, event.Module.Health)
	}
}

// registerModuleHandler creates and registers a handler for a module.
func (dr *DynamicRouter) registerModuleHandler(module *ModuleInfo) {
	if len(module.ProtoDescriptor) == 0 {
		dr.log.Warnf("Module %s has no proto descriptor, skipping dynamic routing", module.ModuleID)
		return
	}

	if err := dr.transcoder.RegisterModule(module.ModuleID, module.GrpcEndpoint, module.ProtoDescriptor); err != nil {
		dr.log.Errorf("Failed to register module %s with transcoder: %v", module.ModuleID, err)
		return
	}

	handler := NewModuleHandler(module.ModuleID, dr.transcoder, dr.log)
	dr.handlers.Store(module.ModuleID, handler)

	dr.log.Infof("Hot-registered dynamic handler for module: %s at endpoint %s",
		module.ModuleID, module.GrpcEndpoint)
}

// unregisterModuleHandler removes a module handler.
func (dr *DynamicRouter) unregisterModuleHandler(moduleID string) {
	dr.handlers.Delete(moduleID)

	if err := dr.transcoder.UnregisterModule(moduleID); err != nil {
		dr.log.Warnf("Failed to unregister module %s from transcoder: %v", moduleID, err)
	}

	dr.log.Infof("Hot-unregistered dynamic handler for module: %s", moduleID)
}

// LoadExistingModules loads handlers for already registered modules.
// This should be called during startup after the registry has loaded from database.
func (dr *DynamicRouter) LoadExistingModules() {
	modules := dr.registry.List()
	for _, module := range modules {
		dr.registerModuleHandler(module)
	}
	dr.log.Infof("Loaded %d existing module handlers", len(modules))
}

// ServeHTTP implements http.Handler for the dynamic router.
// Route format: {routePrefix}{module_id}/{rest_of_path}
func (dr *DynamicRouter) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	moduleID, modulePath := dr.extractModuleFromPath(r.URL.Path)

	if moduleID == "" {
		dr.writeError(w, http.StatusBadRequest, "missing module ID in path")
		return
	}

	// Authenticate: extract Bearer token and set auth claims in request context.
	// The Kratos middleware chain does not cover HandlePrefix routes, so we must
	// authenticate here to ensure the transcoder can inject user metadata.
	r = dr.authenticateRequest(r)

	val, ok := dr.handlers.Load(moduleID)
	if !ok {
		dr.writeError(w, http.StatusNotFound, "module not found: %s", moduleID)
		return
	}

	handler := val.(*ModuleHandler)
	handler.ServeHTTP(w, r, modulePath)
}

// authenticateRequest parses the Bearer token from the Authorization header,
// validates it, and returns a new request with auth claims set in the context.
func (dr *DynamicRouter) authenticateRequest(r *http.Request) *http.Request {
	authHeader := r.Header.Get("Authorization")
	if len(authHeader) <= 7 || !strings.EqualFold(authHeader[:7], "bearer ") {
		dr.log.Warnf("No Bearer token in Authorization header (header length=%d)", len(authHeader))
		return r
	}

	token := authHeader[7:]
	claims, err := dr.authenticator.AuthenticateToken(token)
	if err != nil {
		dr.log.Warnf("Failed to authenticate token for module request: %v", err)
		return r
	}

	ctx := authnEngine.ContextWithAuthClaims(r.Context(), claims)
	return r.WithContext(ctx)
}

// extractModuleFromPath extracts the module ID and remaining path.
// Input:  {routePrefix}echo/v1/messages
// Output: "echo", "/v1/messages"
func (dr *DynamicRouter) extractModuleFromPath(path string) (moduleID, modulePath string) {
	if !strings.HasPrefix(path, dr.routePrefix) {
		return "", ""
	}

	remaining := strings.TrimPrefix(path, dr.routePrefix)
	if remaining == "" {
		return "", ""
	}

	slashIdx := strings.Index(remaining, "/")
	if slashIdx == -1 {
		return remaining, "/"
	}

	return remaining[:slashIdx], remaining[slashIdx:]
}

// writeError writes a JSON error response.
func (dr *DynamicRouter) writeError(w http.ResponseWriter, code int, format string, args ...any) {
	msg := fmt.Sprintf(format, args...)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	if _, err := w.Write([]byte(fmt.Sprintf(`{"code":%d,"message":"%s"}`, code, msg))); err != nil {
		dr.log.Warnf("Failed to write HTTP error response: %v", err)
	}
}

// ListRegisteredModules returns a list of all modules with registered handlers.
func (dr *DynamicRouter) ListRegisteredModules() []string {
	var modules []string
	dr.handlers.Range(func(key, value interface{}) bool {
		modules = append(modules, key.(string))
		return true
	})
	return modules
}

// GetModuleRoutes returns all routes for a specific module.
func (dr *DynamicRouter) GetModuleRoutes(moduleID string) ([]transcoder.RouteInfo, error) {
	methods, err := dr.transcoder.GetModuleMethods(moduleID)
	if err != nil {
		return nil, err
	}

	var routes []transcoder.RouteInfo
	for _, method := range methods {
		for _, rule := range method.HTTPRules {
			routes = append(routes, transcoder.RouteInfo{
				ModuleID:    moduleID,
				ServiceName: method.ServiceName,
				MethodName:  method.MethodName,
				HTTPMethod:  rule.Method,
				Pattern:     dr.routePrefix + moduleID + rule.Pattern,
				FullMethod:  method.FullName,
			})
		}
	}
	return routes, nil
}

// GetAllRoutes returns all routes across all registered modules.
func (dr *DynamicRouter) GetAllRoutes() []transcoder.RouteInfo {
	return dr.transcoder.ListRoutes()
}

// RoutePrefix returns the configured route prefix.
func (dr *DynamicRouter) RoutePrefix() string {
	return dr.routePrefix
}
