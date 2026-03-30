package gateway

// RouterOption configures the DynamicRouter.
type RouterOption func(*DynamicRouter)

// WithRoutePrefix sets the URL prefix that the router matches against.
// Default: "/admin/v1/modules/".
func WithRoutePrefix(prefix string) RouterOption {
	return func(dr *DynamicRouter) {
		dr.routePrefix = prefix
	}
}
