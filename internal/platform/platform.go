// Package platform provides logging, health and metrics endpoints, middleware and the HTTP server lifecycle.
package platform

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Paths of the probes and the metrics. They are served on the same address as the API. A reverse proxy in front of
// the server should not expose them.
const (
	PathLive    = "/.well-known/live"
	PathReady   = "/.well-known/ready"
	PathMetrics = "/metrics"
)

const (
	readHeaderTimeout = 5 * time.Second
	// readTimeout bounds the time to read a whole request, so a client cannot hold a connection by sending its body
	// slowly. Requests are small.
	readTimeout = 10 * time.Second
	// writeTimeout bounds the time from the end of the request headers to the end of the response.
	writeTimeout    = 30 * time.Second
	idleTimeout     = 2 * time.Minute
	shutdownTimeout = 10 * time.Second
	readyTimeout    = 1 * time.Second
)

// NewLogger returns a JSON logger that writes to out.
func NewLogger(out io.Writer, level slog.Level) *slog.Logger {
	return slog.New(slog.NewJSONHandler(out, &slog.HandlerOptions{Level: level}))
}

// NewRegistry returns a metrics registry with the Go runtime and process metrics.
func NewRegistry() *prometheus.Registry {
	reg := prometheus.NewRegistry()
	reg.MustRegister(collectors.NewGoCollector(), collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}))
	return reg
}

// MetricsHandler serves the metrics of reg in the Prometheus text format.
func MetricsHandler(reg prometheus.Gatherer) http.Handler {
	return promhttp.HandlerFor(reg, promhttp.HandlerOpts{})
}

// OKHandler returns 200 "ok". It serves the liveness probe.
func OKHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
}

// ReadyHandler returns 200 if all checks succeed within one second, and 503 otherwise. It serves the readiness probe.
// Without checks it always returns 200.
func ReadyHandler(checks ...func(context.Context) error) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), readyTimeout)
		defer cancel()
		for _, check := range checks {
			if err := check(ctx); err != nil {
				w.WriteHeader(http.StatusServiceUnavailable)
				_, _ = w.Write([]byte("not ready"))
				return
			}
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
}

// Recover logs a panic in next and returns 500 instead of ending the process.
func Recover(log *slog.Logger, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if recovered := recover(); recovered != nil {
				log.Error("panic in http handler", "panic", recovered, "path", r.URL.Path)
				// Has no effect if the handler already wrote the headers.
				w.WriteHeader(http.StatusInternalServerError)
			}
		}()
		next.ServeHTTP(w, r)
	})
}

// Serve runs the HTTP server until ctx is canceled. It then stops accepting connections, waits up to shutdownTimeout
// for running requests and returns.
func Serve(ctx context.Context, log *slog.Logger, addr string, h http.Handler) error {
	srv := &http.Server{
		Addr:              addr,
		Handler:           h,
		ReadHeaderTimeout: readHeaderTimeout,
		ReadTimeout:       readTimeout,
		WriteTimeout:      writeTimeout,
		IdleTimeout:       idleTimeout,
	}
	errc := make(chan error, 1)
	go func() { errc <- srv.ListenAndServe() }()
	log.Info("http server listening", "addr", addr)

	select {
	case err := <-errc:
		return err
	case <-ctx.Done():
		log.Info("shutting down")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
		defer cancel()
		return srv.Shutdown(shutdownCtx)
	}
}
