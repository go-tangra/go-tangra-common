package gateway

// ModuleEventType represents the type of module registry event.
type ModuleEventType int

const (
	ModuleEventRegistered ModuleEventType = iota
	ModuleEventUnregistered
	ModuleEventUpdated
	ModuleEventHealthChanged
)

// ModuleInfo is the subset of module data needed by the router and transcoder.
type ModuleInfo struct {
	ModuleID        string
	GrpcEndpoint    string
	ProtoDescriptor []byte
	Health          string
}

// ModuleEvent represents a module lifecycle event.
type ModuleEvent struct {
	Type   ModuleEventType
	Module *ModuleInfo
}

// ModuleEventHandler is a callback function for module events.
type ModuleEventHandler func(event ModuleEvent)

// ModuleRegistry provides module lookup and lifecycle event subscription.
type ModuleRegistry interface {
	// Get returns a module by its ID. Returns (nil, false) if not found.
	Get(moduleID string) (*ModuleInfo, bool)
	// List returns all registered modules.
	List() []*ModuleInfo
	// OnEvent registers a handler for module lifecycle events.
	OnEvent(handler ModuleEventHandler)
}
