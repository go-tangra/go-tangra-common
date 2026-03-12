package metrics

import (
	"context"
	"time"

	"github.com/go-kratos/kratos/v2/middleware"
	"github.com/go-kratos/kratos/v2/transport"
	"github.com/prometheus/client_golang/prometheus"
)

// NewServerMiddleware returns a Kratos middleware that records gRPC request
// duration and counts using the provided histogram and counter.
// Both parameters are optional — pass nil to skip recording that metric.
func NewServerMiddleware(duration *prometheus.HistogramVec, requests *prometheus.CounterVec) middleware.Middleware {
	return func(handler middleware.Handler) middleware.Handler {
		return func(ctx context.Context, req interface{}) (interface{}, error) {
			start := time.Now()

			reply, err := handler(ctx, req)

			var operation string
			if tr, ok := transport.FromServerContext(ctx); ok {
				operation = tr.Operation()
			}

			status := "OK"
			if err != nil {
				status = "ERROR"
			}

			elapsed := time.Since(start).Seconds()

			if duration != nil && operation != "" {
				duration.WithLabelValues(operation).Observe(elapsed)
			}
			if requests != nil && operation != "" {
				requests.WithLabelValues(operation, status).Inc()
			}

			return reply, err
		}
	}
}
