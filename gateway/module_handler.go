package gateway

import (
	"net/http"

	"github.com/go-kratos/kratos/v2/log"

	"github.com/go-tangra/go-tangra-common/gateway/transcoder"
)

// moduleHandler handles HTTP requests for a specific module.
type moduleHandler struct {
	moduleID   string
	transcoder *transcoder.Transcoder
	log        *log.Helper
}

// newModuleHandler creates a new moduleHandler.
func newModuleHandler(
	moduleID string,
	tc *transcoder.Transcoder,
	logger *log.Helper,
) *moduleHandler {
	return &moduleHandler{
		moduleID:   moduleID,
		transcoder: tc,
		log:        logger,
	}
}

// ServeHTTP handles an HTTP request for this module.
// modulePath is the path relative to the module prefix (e.g., /v1/messages).
func (h *moduleHandler) ServeHTTP(w http.ResponseWriter, r *http.Request, modulePath string) {
	h.log.Debugf("Module %s handling %s %s", h.moduleID, r.Method, modulePath)

	h.transcoder.Handle(
		r.Context(),
		w,
		r,
		h.moduleID,
		modulePath,
	)
}
