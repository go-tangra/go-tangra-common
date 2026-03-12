// Package metrics provides a shared Prometheus metrics server and helpers
// for Go-Tangra microservices.
//
// Each module creates its own gauges/counters via the standard prometheus client,
// then starts a MetricsServer to expose them on /metrics.
//
// Usage:
//
//	srv := metrics.NewMetricsServer(":9090")
//	go srv.Start()
//	defer srv.Stop(ctx)
package metrics

import (
	"context"
	"net/http"
	"time"

	"github.com/go-kratos/kratos/v2/log"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// MetricsServer serves Prometheus metrics over HTTP.
type MetricsServer struct {
	server *http.Server
	log    *log.Helper
}

// NewMetricsServer creates a metrics HTTP server on the given address (e.g. ":9090").
// It uses the provided registry, or the default global registry if nil.
func NewMetricsServer(addr string, registry *prometheus.Registry, logger log.Logger) *MetricsServer {
	mux := http.NewServeMux()

	var handler http.Handler
	if registry != nil {
		handler = promhttp.HandlerFor(registry, promhttp.HandlerOpts{})
	} else {
		handler = promhttp.Handler()
	}

	mux.Handle("/metrics", handler)
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	return &MetricsServer{
		server: &http.Server{
			Addr:              addr,
			Handler:           mux,
			ReadHeaderTimeout: 10 * time.Second,
		},
		log: log.NewHelper(log.With(logger, "component", "metrics-server")),
	}
}

// Start begins serving metrics. This blocks until the server is stopped.
func (s *MetricsServer) Start() error {
	s.log.Infof("Prometheus metrics server listening on %s", s.server.Addr)
	if err := s.server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		s.log.Errorf("Metrics server error: %v", err)
		return err
	}
	return nil
}

// Stop gracefully shuts down the metrics server.
func (s *MetricsServer) Stop(ctx context.Context) error {
	s.log.Info("Stopping metrics server")
	return s.server.Shutdown(ctx)
}
