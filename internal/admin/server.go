// Package admin serves health, readiness, metrics and configuration
// introspection over HTTP.
package admin

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"sync/atomic"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Server is the admin HTTP server.
type Server struct {
	mux     *http.ServeMux
	ready   atomic.Bool
	version string
	config  func() ([]byte, error)
}

// New builds the handler set. config returns the effective configuration as
// YAML.
func New(reg *prometheus.Registry, version string, config func() ([]byte, error)) *Server {
	s := &Server{mux: http.NewServeMux(), version: version, config: config}
	s.mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprintln(w, "ok")
	})
	s.mux.HandleFunc("GET /readyz", func(w http.ResponseWriter, _ *http.Request) {
		if !s.ready.Load() {
			http.Error(w, "not ready", http.StatusServiceUnavailable)
			return
		}
		fmt.Fprintln(w, "ready")
	})
	s.mux.Handle("GET /metrics", promhttp.HandlerFor(reg, promhttp.HandlerOpts{}))
	s.mux.HandleFunc("GET /config", func(w http.ResponseWriter, _ *http.Request) {
		data, err := s.config()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/yaml")
		w.Write(data)
	})
	s.mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprintf(w, "clatto %s\n/healthz /readyz /metrics /config\n", version)
	})
	return s
}

// SetReady flips readiness.
func (s *Server) SetReady(ready bool) { s.ready.Store(ready) }

// Handler returns the HTTP handler.
func (s *Server) Handler() http.Handler { return s.mux }

// Serve listens on addr until ctx is done.
func (s *Server) Serve(ctx context.Context, addr string, log *slog.Logger) error {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	srv := &http.Server{Handler: s.mux, ReadHeaderTimeout: 5 * time.Second}
	errc := make(chan error, 1)
	go func() { errc <- srv.Serve(ln) }()
	log.Info("admin listening", "addr", ln.Addr().String())
	select {
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		return srv.Shutdown(shutdownCtx)
	case err := <-errc:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	}
}
