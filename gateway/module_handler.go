package gateway

import (
	"net/http"

	"github.com/go-kratos/kratos/v2/log"

	"github.com/go-tangra/go-tangra-common/gateway/transcoder"
)

// ModuleHandler handles HTTP requests for a specific module.
type ModuleHandler struct {
	moduleID   string
	transcoder *transcoder.Transcoder
	log        *log.Helper
}

// NewModuleHandler creates a new ModuleHandler.
func NewModuleHandler(
	moduleID string,
	tc *transcoder.Transcoder,
	logger *log.Helper,
) *ModuleHandler {
	return &ModuleHandler{
		moduleID:   moduleID,
		transcoder: tc,
		log:        logger,
	}
}

// ServeHTTP handles an HTTP request for this module.
// modulePath is the path relative to the module prefix (e.g., /v1/messages).
func (h *ModuleHandler) ServeHTTP(w http.ResponseWriter, r *http.Request, modulePath string) {
	h.log.Debugf("Module %s handling %s %s", h.moduleID, r.Method, modulePath)

	h.transcoder.Handle(
		r.Context(),
		w,
		r,
		h.moduleID,
		modulePath,
	)
}

// GetModuleID returns the module ID for this handler.
func (h *ModuleHandler) GetModuleID() string {
	return h.moduleID
}
