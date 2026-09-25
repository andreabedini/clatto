//go:build e2e

// End-to-end test: creates a real tun device in the current network
// namespace, so it must run as root (or in a user namespace that owns a
// fresh network namespace). See test/e2e.sh.
package test

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/andreabedini/clatto/internal/config"
	"github.com/andreabedini/clatto/internal/daemon"
	"github.com/andreabedini/clatto/internal/netconf"
	"github.com/andreabedini/clatto/internal/tundev"
	"github.com/andreabedini/clatto/internal/xlate"
)

const e2eYAML = `
interface: {name: clat-e2e, sysctl: false}
ipv4_address: 10.0.0.254
ipv6_address: 2001:db8::fe
prefix: 64:ff9b::/96
wkpf_strict: false
maps:
  - {ipv4: 10.0.0.2, ipv6: 2001:db8::1}
`

func routes(t *testing.T, family, dev string) string {
	t.Helper()
	out, err := exec.Command("ip", family, "route", "show", "dev", dev).CombinedOutput()
	if err != nil {
		t.Fatalf("ip route: %v: %s", err, out)
	}
	return string(out)
}

// TestReloadUpdatesRoutes applies a new configuration through the daemon and
// checks that routes are added and removed on the real interface.
func TestReloadUpdatesRoutes(t *testing.T) {
	if _, err := os.Stat("/dev/net/tun"); err != nil {
		t.Skip("/dev/net/tun not available")
	}
	var cfg config.Config
	if err := config.LoadYAML(&cfg, []byte(e2eYAML)); err != nil {
		t.Fatal(err)
	}
	r, err := config.Resolve(cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	d := daemon.New(r, daemon.Options{Log: slog.Default(), Registry: prometheus.NewRegistry()})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- d.Run(ctx) }()
	for !d.Ready() {
		select {
		case err := <-done:
			t.Fatalf("daemon: %v", err)
		default:
			time.Sleep(5 * time.Millisecond)
		}
	}
	if !strings.Contains(routes(t, "-4", "clat-e2e"), "10.0.0.2 ") {
		t.Fatalf("initial route missing:\n%s", routes(t, "-4", "clat-e2e"))
	}
	updated := strings.Replace(e2eYAML, "{ipv4: 10.0.0.2, ipv6: 2001:db8::1}", "{ipv4: 10.0.0.3, ipv6: 2001:db8::3}\n  - {ipv4: 10.0.1.0/24, ipv6: 2001:db8:1::/120}", 1)
	if err := d.ApplyYAML([]byte(updated), "e2e"); err != nil {
		t.Fatal(err)
	}
	v4, v6 := routes(t, "-4", "clat-e2e"), routes(t, "-6", "clat-e2e")
	if strings.Contains(v4, "10.0.0.2 ") || !strings.Contains(v4, "10.0.0.3 ") || !strings.Contains(v4, "10.0.1.0/24") {
		t.Errorf("IPv4 routes not updated:\n%s", v4)
	}
	// The IPv6 side of a static map is never routed into the device: it
	// is a real host, and a route would loop translated packets back.
	if strings.Contains(v6, "2001:db8::1 ") || strings.Contains(v6, "2001:db8::3 ") || strings.Contains(v6, "2001:db8:1::/120") || !strings.Contains(v6, "64:ff9b::/96") || !strings.Contains(v6, "2001:db8::fe ") {
		t.Errorf("IPv6 routes wrong:\n%s", v6)
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

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
	if err := netconf.Apply(netconf.Options{Name: r.Config.Interface.Name, Addresses: r.Addresses, Routes4: r.Routes4, Routes6: r.Routes6}, slog.Default()); err != nil {
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
}

func ip(t *testing.T, args ...string) string {
	t.Helper()
	out, err := exec.Command("ip", args...).CombinedOutput()
	if err != nil {
		t.Fatalf("ip %v: %v: %s", args, err, out)
	}
	return string(out)
}

// TestSharedAddressRules checks the policy routing for a shared address on
// lo: the local table rule is demoted, rules follow the filters across
// updates, and everything is idempotent. No tun device is needed.
func TestSharedAddressRules(t *testing.T) {
	if out, err := exec.Command("ip", "-6", "rule", "add", "prio", "30000", "table", "30000").CombinedOutput(); err != nil {
		t.Skipf("cannot manage rules here: %v: %s", err, out)
	}
	ip(t, "-6", "rule", "del", "prio", "30000", "table", "30000")
	log := slog.Default()
	addr := netip.MustParseAddr("2001:db8::7")
	tcp := netconf.Filter{Proto: 6, Start: 61000, End: 61099}
	udp := netconf.Filter{Proto: 17, Start: 5000, End: 5000}
	shared := func(f ...netconf.Filter) *netconf.Shared {
		return &netconf.Shared{Addr: addr, From: netip.MustParsePrefix("64:ff9b::/96"), Table: 0xc1a7, Filters: f}
	}
	want := func(step string, rules int, route bool) {
		t.Helper()
		out := ip(t, "-6", "rule", "show")
		if n := strings.Count(out, "lookup 49575"); n != rules {
			t.Errorf("%s: %d rules for table 49575, want %d:\n%s", step, n, rules, out)
		}
		if rules > 0 && (strings.Contains(out, "0:\tfrom all lookup local") || !strings.Contains(out, "2:\tfrom all lookup local")) {
			t.Errorf("%s: local table rule not demoted:\n%s", step, out)
		}
		tbl := ip(t, "-6", "route", "show", "table", "49575")
		if strings.Contains(tbl, "2001:db8::7") != route {
			t.Errorf("%s: table route present=%v, want %v:\n%s", step, !route, route, tbl)
		}
	}
	first := netconf.Options{Name: "lo", Shared: shared(tcp, udp)}
	for i := 0; i < 2; i++ {
		if err := netconf.Apply(first, log); err != nil {
			t.Fatalf("apply %d: %v", i, err)
		}
		want("apply", 2, true)
	}
	out := ip(t, "-6", "rule", "show")
	if !strings.Contains(out, "from 64:ff9b::/96 to 2001:db8::7 ipproto tcp dport 61000-61099 lookup 49575") {
		t.Errorf("tcp rule missing:\n%s", out)
	}
	second := netconf.Options{Name: "lo", Shared: shared(udp)}
	if err := netconf.Update(first, second, log); err != nil {
		t.Fatal(err)
	}
	want("update", 1, true)
	if strings.Contains(ip(t, "-6", "rule", "show"), "ipproto tcp") {
		t.Error("tcp rule survived the update")
	}
	if err := netconf.Update(second, netconf.Options{Name: "lo"}, log); err != nil {
		t.Fatal(err)
	}
	want("remove", 0, false)
}

// TestSharedAddressCLAT runs a CLAT that shares lo's own address
// 2001:db8::7 and detects it automatically. An IPv4 socket on 192.0.0.1
// talks to "10.0.0.9", which is really an IPv6 UDP echo server on
// 64:ff9b::10.0.0.9 (also on lo, standing in for a host behind the PLAT).
// Replies to the shared address only reach the IPv4 socket because the
// policy rule runs before the local table.
func TestSharedAddressCLAT(t *testing.T) {
	if _, err := os.Stat("/dev/net/tun"); err != nil {
		t.Skip("/dev/net/tun not available")
	}
	ip(t, "link", "set", "lo", "up")
	ip(t, "addr", "add", "2001:db8::7/128", "dev", "lo")
	ip(t, "addr", "add", "64:ff9b::10.0.0.9/128", "dev", "lo")
	// What "ip -6 route get 64:ff9b::" reports as src is the shared address.
	ip(t, "-6", "route", "add", "64:ff9b::/96", "dev", "lo", "src", "2001:db8::7")

	// wkpf_strict is off because 10.0.0.9 is private and would be
	// rejected through the well-known prefix, as in TestUDPThroughTranslator.
	y := `
interface: {name: clat-shared, sysctl: false}
prefix: 64:ff9b::/96
wkpf_strict: false
log: {packets: [drop, reject, icmp]}
clat: {ipv6_address: auto}
`
	var cfg config.Config
	if err := config.LoadYAML(&cfg, []byte(y)); err != nil {
		t.Fatal(err)
	}
	r, err := config.ResolveWith(cfg, config.ResolveOptions{SourceAddr: netconf.SourceAddress})
	if err != nil {
		t.Fatal(err)
	}
	if r.Config.CLAT.IPv6Address != "2001:db8::7" {
		t.Fatalf("detected %q", r.Config.CLAT.IPv6Address)
	}
	d := daemon.New(r, daemon.Options{Log: slog.Default(), Registry: prometheus.NewRegistry()})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- d.Run(ctx) }()
	for !d.Ready() {
		select {
		case err := <-done:
			t.Fatalf("daemon: %v", err)
		default:
			time.Sleep(5 * time.Millisecond)
		}
	}
	if v4 := routes(t, "-4", "clat-shared"); !strings.Contains(v4, "default ") {
		t.Errorf("no IPv4 default route:\n%s", v4)
	}

	server, err := net.ListenUDP("udp6", &net.UDPAddr{IP: net.ParseIP("64:ff9b::10.0.0.9")})
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
			if from.IP.String() != "2001:db8::7" {
				t.Errorf("server saw source %s, want the shared address 2001:db8::7", from.IP)
			}
			server.WriteToUDP(buf[:n], from)
		}
	}()
	client, err := net.DialUDP("udp4", &net.UDPAddr{IP: net.IPv4(192, 0, 0, 1)}, &net.UDPAddr{IP: net.IPv4(10, 0, 0, 9), Port: port})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	clientPort := client.LocalAddr().(*net.UDPAddr).Port
	echo := func(step string, want bool) {
		t.Helper()
		msg := []byte("hello through the clat " + step)
		if _, err := client.Write(msg); err != nil {
			t.Fatalf("%s: write: %v", step, err)
		}
		buf := make([]byte, 2000)
		client.SetReadDeadline(time.Now().Add(2 * time.Second))
		n, err := client.Read(buf)
		switch {
		case want && err != nil:
			t.Fatalf("%s: no echo: %v (stats %+v)\nrules:\n%s", step, err, d.Engine().Stats(), ip(t, "-6", "rule", "show"))
		case want && string(buf[:n]) != string(msg):
			t.Fatalf("%s: echo mismatch", step)
		case !want && err == nil:
			t.Fatalf("%s: echo arrived although the reply port is filtered out", step)
		}
	}
	echo("unfiltered", true)

	// Restrict return traffic to the client's port: still works.
	filtered := strings.Replace(y, "clat: {ipv6_address: auto}", fmt.Sprintf("clat: {ipv6_address: auto, ports: [udp/%d, icmp]}", clientPort), 1)
	if err := d.ApplyYAML([]byte(filtered), "e2e"); err != nil {
		t.Fatal(err)
	}
	if out := ip(t, "-6", "rule", "show"); !strings.Contains(out, fmt.Sprintf("ipproto udp dport %d lookup", clientPort)) {
		t.Fatalf("filtered rule missing:\n%s", out)
	}
	echo("filtered", true)

	// Restrict it to some other port: the reply stays with the IPv6
	// stack and never reaches the IPv4 socket.
	other := strings.Replace(y, "clat: {ipv6_address: auto}", "clat: {ipv6_address: auto, ports: [udp/1]}", 1)
	if err := d.ApplyYAML([]byte(other), "e2e"); err != nil {
		t.Fatal(err)
	}
	echo("other port", false)

	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

// TestUDPFromIPv4 sends the other way: an IPv4 client on 10.0.0.1 reaches
// the IPv6 host 2001:db8::1 through its static map 10.0.0.2. The map's
// IPv6 side is a local address here, as a real host would be reachable
// through the network; only the IPv4 side is routed into the device.
func TestUDPFromIPv4(t *testing.T) {
	if _, err := os.Stat("/dev/net/tun"); err != nil {
		t.Skip("/dev/net/tun not available")
	}
	ip(t, "link", "set", "lo", "up")
	for _, a := range []string{"10.0.0.1/32", "2001:db8::1/128"} {
		// Earlier tests may have added the address already.
		if out, err := exec.Command("ip", "addr", "add", a, "dev", "lo").CombinedOutput(); err != nil && !strings.Contains(string(out), "File exists") && !strings.Contains(string(out), "already assigned") {
			t.Fatalf("ip addr add %s: %v: %s", a, err, out)
		}
	}
	var cfg config.Config
	if err := config.LoadYAML(&cfg, []byte(`
interface: {name: clat-e2e4, sysctl: false}
ipv4_address: 10.0.0.254
ipv6_address: 2001:db8::fe
prefix: 64:ff9b::/96
wkpf_strict: false
log: {packets: [drop, reject, icmp]}
maps:
  - {ipv4: 10.0.0.2, ipv6: 2001:db8::1}
`)); err != nil {
		t.Fatal(err)
	}
	r, err := config.Resolve(cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	d := daemon.New(r, daemon.Options{Log: slog.Default(), Registry: prometheus.NewRegistry()})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- d.Run(ctx) }()
	for !d.Ready() {
		select {
		case err := <-done:
			t.Fatalf("daemon: %v", err)
		default:
			time.Sleep(5 * time.Millisecond)
		}
	}
	if v6 := routes(t, "-6", "clat-e2e4"); strings.Contains(v6, "2001:db8::1 ") {
		t.Fatalf("static map's IPv6 side routed into the device:\n%s", v6)
	}

	server, err := net.ListenUDP("udp6", &net.UDPAddr{IP: net.ParseIP("2001:db8::1")})
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
			if from.IP.String() != "64:ff9b::a00:1" {
				t.Errorf("server saw source %s, want 64:ff9b::10.0.0.1", from.IP)
			}
			server.WriteToUDP(buf[:n], from)
		}
	}()
	client, err := net.DialUDP("udp4", &net.UDPAddr{IP: net.IPv4(10, 0, 0, 1)}, &net.UDPAddr{IP: net.IPv4(10, 0, 0, 2), Port: port})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	msg := []byte("hello from IPv4")
	if _, err := client.Write(msg); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 2000)
	client.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, err := client.Read(buf)
	if err != nil {
		t.Fatalf("no echo: %v (stats %+v)", err, d.Engine().Stats())
	}
	if string(buf[:n]) != string(msg) {
		t.Fatalf("echo mismatch")
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}
