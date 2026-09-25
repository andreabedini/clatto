package daemon

import (
	"context"
	"encoding/binary"
	"errors"
	"log/slog"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/andreabedini/clatto/internal/config"
	"github.com/andreabedini/clatto/internal/tundev"
)

const baseYAML = `
interface: {name: fake0, configure: false}
ipv4_address: 192.0.2.1
ipv6_address: 2001:db8::1
prefix: 64:ff9b::/96
maps:
  - {ipv4: 192.0.2.10, ipv6: 2001:db8::10}
dynamic_pool: {prefix: 192.0.2.128/25}
http: {listen: off}
`

func resolve(t *testing.T, y string) *config.Resolved {
	t.Helper()
	var cfg config.Config
	if err := config.LoadYAML(&cfg, []byte(y)); err != nil {
		t.Fatal(err)
	}
	r, err := config.Resolve(cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

// udp6 builds an IPv6 UDP packet from src to dst.
func udp6(src, dst string) []byte {
	udp := make([]byte, 16)
	binary.BigEndian.PutUint16(udp[0:], 1111)
	binary.BigEndian.PutUint16(udp[2:], 2222)
	binary.BigEndian.PutUint16(udp[4:], uint16(len(udp)))
	binary.BigEndian.PutUint16(udp[6:], 0x1234)
	pkt := make([]byte, 40+len(udp))
	pkt[0] = 0x60
	binary.BigEndian.PutUint16(pkt[4:], uint16(len(udp)))
	pkt[6] = 17
	pkt[7] = 64
	s := netip.MustParseAddr(src).As16()
	d := netip.MustParseAddr(dst).As16()
	copy(pkt[8:], s[:])
	copy(pkt[24:], d[:])
	copy(pkt[40:], udp)
	return pkt
}

func startDaemon(t *testing.T) (*Daemon, *tundev.FakeDevice, context.CancelFunc) {
	t.Helper()
	dev := tundev.NewFakeDevice(4, 1500)
	d := New(resolve(t, baseYAML), Options{
		Log:              slog.Default(),
		Registry:         prometheus.NewRegistry(),
		NewDevice:        func(string, int) (tundev.Device, error) { return dev, nil },
		MaintainInterval: 50 * time.Millisecond,
	})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- d.Run(ctx) }()
	deadline := time.Now().Add(2 * time.Second)
	for !d.Ready() && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if !d.Ready() {
		t.Fatal("daemon not ready")
	}
	t.Cleanup(func() {
		cancel()
		if err := <-done; err != nil {
			t.Errorf("run: %v", err)
		}
	})
	return d, dev, cancel
}

func expect(t *testing.T, dev *tundev.FakeDevice, check func([]byte) bool, what string) {
	t.Helper()
	select {
	case out := <-dev.Out:
		if !check(out) {
			t.Fatalf("%s: unexpected output %x", what, out[:min(len(out), 48)])
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("%s: no output", what)
	}
}

func isIPv4UDPFrom(src string) func([]byte) bool {
	return func(b []byte) bool {
		return b[0]>>4 == 4 && b[9] == 17 && netip.AddrFrom4([4]byte(b[12:16])) == netip.MustParseAddr(src)
	}
}

func isICMPv6Unreachable(code byte) func([]byte) bool {
	return func(b []byte) bool { return b[0]>>4 == 6 && b[6] == 58 && b[40] == 1 && b[41] == code }
}

func TestApplyReplacesMappings(t *testing.T) {
	d, dev, _ := startDaemon(t)

	dev.Inject(udp6("2001:db8::10", "64:ff9b::8.8.8.8"))
	expect(t, dev, isIPv4UDPFrom("192.0.2.10"), "initial static map")

	// A pool host gets an address; note it for later.
	dev.Inject(udp6("2001:db8::77", "64:ff9b::8.8.8.8"))
	var poolAddr string
	expect(t, dev, func(b []byte) bool {
		poolAddr = netip.AddrFrom4([4]byte(b[12:16])).String()
		return b[0]>>4 == 4 && strings.HasPrefix(poolAddr, "192.0.2.")
	}, "pool assignment")

	// Replace the static map; keep the pool.
	err := d.ApplyYAML([]byte(strings.Replace(baseYAML, "2001:db8::10", "2001:db8::11", 1)), "test")
	if err != nil {
		t.Fatal(err)
	}
	if st := d.Status(); st.Generation != 2 || st.Source != "test" || st.LastError != "" {
		t.Errorf("status %+v", st)
	}
	dev.Inject(udp6("2001:db8::11", "64:ff9b::8.8.8.8"))
	expect(t, dev, isIPv4UDPFrom("192.0.2.10"), "new static map")
	// The old host now falls into the pool and gets a different address.
	dev.Inject(udp6("2001:db8::10", "64:ff9b::8.8.8.8"))
	expect(t, dev, func(b []byte) bool {
		return isIPv4UDPFrom("192.0.2.10")(b) == false && b[0]>>4 == 4
	}, "old host via pool")
	// The pool host kept its assignment across the reload.
	dev.Inject(udp6("2001:db8::77", "64:ff9b::8.8.8.8"))
	expect(t, dev, isIPv4UDPFrom(poolAddr), "pool assignment preserved")

	// Dropping the pool: unknown hosts are rejected.
	err = d.ApplyYAML([]byte(strings.Replace(baseYAML, "dynamic_pool: {prefix: 192.0.2.128/25}", "", 1)), "test")
	if err != nil {
		t.Fatal(err)
	}
	if d.Pool() != nil {
		t.Fatal("pool should be gone")
	}
	dev.Inject(udp6("2001:db8::77", "64:ff9b::8.8.8.8"))
	expect(t, dev, isICMPv6Unreachable(5), "no pool")
}

func TestApplyRejectsBadAndImmutable(t *testing.T) {
	d, dev, _ := startDaemon(t)

	err := d.ApplyYAML([]byte("ipv4_address: not-an-address\n"), "test")
	if !errors.Is(err, ErrInvalid) {
		t.Fatalf("expected ErrInvalid, got %v", err)
	}
	err = d.ApplyYAML([]byte(strings.Replace(baseYAML, "name: fake0", "name: other0", 1)), "test")
	if err == nil || !strings.Contains(err.Error(), "interface.name") {
		t.Fatalf("expected immutable error, got %v", err)
	}
	st := d.Status()
	if st.Generation != 1 || st.LastError == "" {
		t.Errorf("status %+v", st)
	}
	// Still translating with the original config.
	dev.Inject(udp6("2001:db8::10", "64:ff9b::8.8.8.8"))
	expect(t, dev, isIPv4UDPFrom("192.0.2.10"), "original config intact")

	if err := d.Reload("test"); !errors.Is(err, ErrInvalid) {
		t.Fatalf("reload without file: %v", err)
	}
}

func TestWatchFileReloads(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte(baseYAML), 0o644); err != nil {
		t.Fatal(err)
	}
	dev := tundev.NewFakeDevice(4, 1500)
	d := New(resolve(t, baseYAML), Options{
		Log:       slog.Default(),
		Registry:  prometheus.NewRegistry(),
		NewDevice: func(string, int) (tundev.Device, error) { return dev, nil },
		LoadFile: func() (config.Config, error) {
			var cfg config.Config
			err := config.LoadFile(&cfg, path)
			return cfg, err
		},
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go d.Run(ctx)
	go d.WatchFile(ctx, path, 10*time.Millisecond)

	// Replace the file atomically, as a ConfigMap volume does; writing in
	// place lets the watcher read a truncated document.
	replace := func(data string) {
		t.Helper()
		tmp := path + ".tmp"
		if err := os.WriteFile(tmp, []byte(data), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.Rename(tmp, path); err != nil {
			t.Fatal(err)
		}
	}
	time.Sleep(30 * time.Millisecond) // let the watcher take its baseline
	replace(strings.Replace(baseYAML, "2001:db8::10", "2001:db8::12", 1))
	deadline := time.Now().Add(2 * time.Second)
	for d.Status().Generation < 2 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	st := d.Status()
	if st.Generation != 2 || st.Source != "file" {
		t.Fatalf("status %+v", st)
	}
	data, _ := d.ConfigYAML()
	if !strings.Contains(string(data), "2001:db8::12") {
		t.Fatalf("config not updated: %s", data)
	}
	// A broken file is rejected and the good config stays.
	replace("ipv4_address: nope\n")
	deadline = time.Now().Add(2 * time.Second)
	for d.Status().LastError == "" && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if st := d.Status(); st.Generation != 2 || st.LastError == "" {
		t.Fatalf("status after bad file %+v", st)
	}
}
