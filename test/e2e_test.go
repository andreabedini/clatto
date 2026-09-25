//go:build e2e

// End-to-end test: creates a real tun device in the current network
// namespace, so it must run as root (or in a user namespace that owns a
// fresh network namespace). See test/e2e.sh.
package test

import (
	"context"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"testing"
	"time"

	"github.com/andreabedini/clatto/internal/config"
	"github.com/andreabedini/clatto/internal/netconf"
	"github.com/andreabedini/clatto/internal/tundev"
	"github.com/andreabedini/clatto/internal/xlate"
)

func TestUDPThroughTranslator(t *testing.T) {
	if _, err := os.Stat("/dev/net/tun"); err != nil {
		t.Skip("/dev/net/tun not available")
	}
	// The kernel side of this test lives on lo: 10.0.0.1 answers UDP on
	// IPv4, 2001:db8::1 is the IPv6 client. clatto maps 2001:db8::1 to
	// 10.0.0.2 and embeds 10.0.0.1 in 64:ff9b::/96.
	for _, args := range [][]string{
		{"link", "set", "lo", "up"},
		{"addr", "add", "10.0.0.1/32", "dev", "lo"},
		{"addr", "add", "2001:db8::1/128", "dev", "lo"},
	} {
		if out, err := exec.Command("ip", args...).CombinedOutput(); err != nil {
			t.Fatalf("ip %v: %v: %s", args, err, out)
		}
	}

	var cfg config.Config
	if err := config.LoadYAML(&cfg, []byte(`
interface: {name: clat-e2e, sysctl: false}
ipv4_address: 10.0.0.254
ipv6_address: 2001:db8::fe
prefix: 64:ff9b::/96
wkpf_strict: false
maps:
  - {ipv4: 10.0.0.2, ipv6: 2001:db8::1}
`)); err != nil {
		t.Fatal(err)
	}
	r, err := config.Resolve(cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	dev, err := tundev.Create(r.Config.Interface.Name, r.Config.Interface.MTU)
	if err != nil {
		t.Fatalf("create tun: %v", err)
	}
	if err := netconf.Apply(netconf.Options{Name: r.Config.Interface.Name, Routes4: r.Routes4, Routes6: r.Routes6}, slog.Default()); err != nil {
		t.Fatal(err)
	}
	eng := tundev.NewEngine(dev, xlate.New(r.Xlate, r.Table, nil), slog.Default())
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go eng.Run(ctx)

	server, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(10, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	port := server.LocalAddr().(*net.UDPAddr).Port
	go func() {
		buf := make([]byte, 2000)
		for {
			n, from, err := server.ReadFromUDP(buf)
			if err != nil {
				return
			}
			if from.IP.String() != "10.0.0.2" {
				t.Errorf("server saw source %s, want 10.0.0.2", from.IP)
			}
			server.WriteToUDP(buf[:n], from)
		}
	}()

	client, err := net.DialUDP("udp6",
		&net.UDPAddr{IP: net.ParseIP("2001:db8::1")},
		&net.UDPAddr{IP: net.ParseIP("64:ff9b::10.0.0.1"), Port: port})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	client.SetDeadline(time.Now().Add(3 * time.Second))
	for _, size := range []int{10, 1000, 1400} {
		msg := make([]byte, size)
		for i := range msg {
			msg[i] = byte(i)
		}
		if _, err := client.Write(msg); err != nil {
			t.Fatal(err)
		}
		buf := make([]byte, 2000)
		n, err := client.Read(buf)
		if err != nil {
			t.Fatalf("size %d: no echo: %v (stats %+v)", size, err, eng.Stats())
		}
		if n != size || string(buf[:n]) != string(msg) {
			t.Fatalf("size %d: echo mismatch", size)
		}
	}
	_ = netip.Addr{}
}
