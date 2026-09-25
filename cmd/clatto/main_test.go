package main

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestProbeURL(t *testing.T) {
	cases := map[[2]string]string{
		{":6464", "/readyz"}:          "http://127.0.0.1:6464/readyz",
		{"0.0.0.0:6464", "readyz"}:    "http://127.0.0.1:6464/readyz",
		{"[::]:6464", "/healthz"}:     "http://127.0.0.1:6464/healthz",
		{"127.0.0.1:9999", "/readyz"}: "http://127.0.0.1:9999/readyz",
		{"[fd00::1]:6464", "/readyz"}: "http://[fd00::1]:6464/readyz",
		{"10.0.0.5:6464", "/config"}:  "http://10.0.0.5:6464/config",
	}
	for in, want := range cases {
		if got := probeURL(in[0], in[1]); got != want {
			t.Errorf("probeURL(%q, %q) = %q, want %q", in[0], in[1], got, want)
		}
	}
}

func TestRunProbe(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/readyz" {
			http.Error(w, "not ready", http.StatusServiceUnavailable)
			return
		}
		fmt.Fprintln(w, "ok")
	}))
	defer srv.Close()
	listen := strings.TrimPrefix(srv.URL, "http://")
	if got := runProbe(probeURL(listen, "/healthz")); got != 0 {
		t.Errorf("healthz exit %d", got)
	}
	if got := runProbe(probeURL(listen, "/readyz")); got != 1 {
		t.Errorf("readyz exit %d", got)
	}
	srv.Close()
	if got := runProbe(probeURL(listen, "/healthz")); got != 1 {
		t.Errorf("closed listener exit %d", got)
	}
}
