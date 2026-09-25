package admin

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/andreabedini/clatto/internal/addrmap"
	"github.com/andreabedini/clatto/internal/daemon"
)

type fakeCtrl struct {
	cfg     string
	applied []string
	err     error
}

func (f *fakeCtrl) Ready() bool                 { return true }
func (f *fakeCtrl) Status() daemon.Status       { return daemon.Status{Generation: 3, Source: "file"} }
func (f *fakeCtrl) ConfigYAML() ([]byte, error) { return []byte(f.cfg), nil }
func (f *fakeCtrl) Reload(string) error         { return f.err }
func (f *fakeCtrl) Pool() *addrmap.Pool         { return nil }
func (f *fakeCtrl) ApplyYAML(b []byte, src string) error {
	if f.err != nil {
		return f.err
	}
	f.applied = append(f.applied, string(b))
	f.cfg = string(b)
	return nil
}

func do(t *testing.T, h http.Handler, method, path, body string) (int, string) {
	t.Helper()
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	b, _ := io.ReadAll(rr.Result().Body)
	return rr.Code, string(b)
}

func TestEndpoints(t *testing.T) {
	ctrl := &fakeCtrl{cfg: "ipv4_address: 1.2.3.4\n"}
	ro := New(prometheus.NewRegistry(), "test", ctrl, false).Handler()
	rw := New(prometheus.NewRegistry(), "test", ctrl, true).Handler()

	if code, body := do(t, ro, "GET", "/healthz", ""); code != 200 || body != "ok\n" {
		t.Errorf("healthz %d %q", code, body)
	}
	if code, _ := do(t, ro, "GET", "/readyz", ""); code != 200 {
		t.Errorf("readyz %d", code)
	}
	if code, body := do(t, ro, "GET", "/config", ""); code != 200 || body != ctrl.cfg {
		t.Errorf("config %d %q", code, body)
	}
	if code, body := do(t, ro, "GET", "/config/status", ""); code != 200 || !strings.Contains(body, `"generation": 3`) {
		t.Errorf("status %d %q", code, body)
	}
	if code, _ := do(t, ro, "GET", "/dynamic", ""); code != 404 {
		t.Errorf("dynamic without pool %d", code)
	}
	if code, _ := do(t, ro, "PUT", "/config", "x: 1\n"); code != 403 {
		t.Errorf("put without admin %d", code)
	}
	if code, _ := do(t, ro, "POST", "/config/reload", ""); code != 403 {
		t.Errorf("reload without admin %d", code)
	}
	if code, body := do(t, rw, "PUT", "/config", "ipv4_address: 5.6.7.8\n"); code != 200 || body != "ipv4_address: 5.6.7.8\n" {
		t.Errorf("put %d %q", code, body)
	}
	if len(ctrl.applied) != 1 {
		t.Errorf("applied %v", ctrl.applied)
	}
	if code, _ := do(t, rw, "POST", "/config/reload", ""); code != 200 {
		t.Errorf("reload %d", code)
	}
	ctrl.err = daemon.ErrInvalid
	if code, _ := do(t, rw, "PUT", "/config", "bad"); code != 400 {
		t.Errorf("invalid put %d", code)
	}
	if code, _ := do(t, ro, "GET", "/metrics", ""); code != 200 {
		t.Errorf("metrics %d", code)
	}
}
