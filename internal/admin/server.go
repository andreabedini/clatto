// Package admin serves health, readiness, metrics and configuration over
// HTTP.
package admin

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/andreabedini/clatto/internal/addrmap"
	"github.com/andreabedini/clatto/internal/daemon"
)

// Controller is what the HTTP layer needs from the daemon.
type Controller interface {
	Ready() bool
	Status() daemon.Status
	ConfigYAML() ([]byte, error)
	ApplyYAML(data []byte, source string) error
	Reload(source string) error
	Pool() *addrmap.Pool
}

// Server is the admin HTTP server.
type Server struct {
	mux   *http.ServeMux
	ctrl  Controller
	admin bool
}

const maxConfigBody = 1 << 20

// New builds the handler set. When admin is false the endpoints that change
// configuration answer 403.
func New(reg *prometheus.Registry, version string, ctrl Controller, admin bool) *Server {
	s := &Server{mux: http.NewServeMux(), ctrl: ctrl, admin: admin}
	m := s.mux
	m.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprintln(w, "ok")
	})
	m.HandleFunc("GET /readyz", func(w http.ResponseWriter, _ *http.Request) {
		if !ctrl.Ready() {
			http.Error(w, "not ready", http.StatusServiceUnavailable)
			return
		}
		fmt.Fprintln(w, "ready")
	})
	m.Handle("GET /metrics", promhttp.HandlerFor(reg, promhttp.HandlerOpts{}))
	m.HandleFunc("GET /config", s.getConfig)
	m.HandleFunc("PUT /config", s.putConfig)
	m.HandleFunc("POST /config", s.putConfig)
	m.HandleFunc("POST /config/reload", s.reload)
	m.HandleFunc("GET /config/status", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, ctrl.Status())
	})
	m.HandleFunc("GET /dynamic", func(w http.ResponseWriter, _ *http.Request) {
		pool := ctrl.Pool()
		if pool == nil {
			http.Error(w, "no dynamic pool configured", http.StatusNotFound)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"prefix":      pool.Prefix().String(),
			"stats":       pool.Stats(),
			"assignments": pool.Assignments(),
		})
	})
	m.HandleFunc("GET /{$}", func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprintf(w, "clatto %s\nGET /healthz /readyz /metrics /config /config/status /dynamic\n", version)
		if admin {
			fmt.Fprintln(w, "PUT /config  POST /config/reload")
		}
	})
	return s
}

func (s *Server) getConfig(w http.ResponseWriter, _ *http.Request) {
	data, err := s.ctrl.ConfigYAML()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/yaml")
	w.Write(data)
}

func (s *Server) putConfig(w http.ResponseWriter, r *http.Request) {
	if !s.admin {
		http.Error(w, "configuration changes are disabled; set http.admin: true", http.StatusForbidden)
		return
	}
	data, err := io.ReadAll(io.LimitReader(r.Body, maxConfigBody+1))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if len(data) > maxConfigBody {
		http.Error(w, "configuration too large", http.StatusRequestEntityTooLarge)
		return
	}
	if err := s.ctrl.ApplyYAML(data, "api"); err != nil {
		writeApplyError(w, err)
		return
	}
	s.getConfig(w, r)
}

func (s *Server) reload(w http.ResponseWriter, r *http.Request) {
	if !s.admin {
		http.Error(w, "configuration changes are disabled; set http.admin: true", http.StatusForbidden)
		return
	}
	if err := s.ctrl.Reload("api"); err != nil {
		writeApplyError(w, err)
		return
	}
	s.getConfig(w, r)
}

func writeApplyError(w http.ResponseWriter, err error) {
	code := http.StatusInternalServerError
	if errors.Is(err, daemon.ErrInvalid) {
		code = http.StatusBadRequest
	}
	http.Error(w, err.Error(), code)
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.Encode(v)
}

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
	log.Info("admin listening", "addr", ln.Addr().String(), "admin", s.admin)
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
