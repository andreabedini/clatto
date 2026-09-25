package config

import (
	"fmt"
	"net/netip"
	"reflect"
	"strings"
	"testing"

	"github.com/andreabedini/clatto/internal/netconf"
	"github.com/andreabedini/clatto/internal/xlate"
)

const sample = `
interface:
  name: nat64
  mtu: 1400
ipv4_address: 192.168.255.1
prefix: 2001:db8:1:ffff::/96
maps:
  - ipv4: 192.168.5.42
    ipv6: 2001:db8:1:4444::1
  - ipv4: 10.1.0.0/24
    ipv6: 2001:db8:1:5555::/120
dynamic_pool:
  prefix: 192.168.255.0/24
  min_lease: 1h
udp_checksum: calc
log:
  level: debug
  format: text
  packets: [drop, reject]
http:
  listen: ":9999"
`

func TestLoadYAMLAndResolve(t *testing.T) {
	var cfg Config
	if err := LoadYAML(&cfg, []byte(sample)); err != nil {
		t.Fatal(err)
	}
	r, err := Resolve(cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	if r.Config.Interface.Name != "nat64" || r.Xlate.MTU != 1400 || r.Xlate.OfflinkMTU != 1280 {
		t.Errorf("interface: %+v xlate %+v", r.Config.Interface, r.Xlate)
	}
	if r.Xlate.LocalAddr6 != netip.MustParseAddr("2001:db8:1:ffff::192.168.255.1") {
		t.Errorf("derived ipv6 address %s", r.Xlate.LocalAddr6)
	}
	if r.Xlate.UDPChecksum != xlate.UDPChecksumCalc {
		t.Errorf("udp mode %s", r.Xlate.UDPChecksum)
	}
	if r.Pool == nil {
		t.Fatal("no pool")
	}
	if r.HTTPListen != ":9999" || !r.PacketKinds[xlate.KindDrop] || r.PacketKinds[xlate.KindSelf] || r.LogJSON {
		t.Errorf("log/http: %+v", r)
	}
	want4 := "10.1.0.0/24 192.168.255.0/24 192.168.255.1/32 192.168.5.42/32"
	// The IPv6 side of the static maps is not routed: those are real hosts.
	want6 := "2001:db8:1:ffff::/96"
	if got := joinPrefixes(r.Routes4); got != want4 {
		t.Errorf("routes4 %q want %q", got, want4)
	}
	if got := joinPrefixes(r.Routes6); got != want6 {
		t.Errorf("routes6 %q want %q", got, want6)
	}
	// Self address maps.
	v6, err := r.Table.MapIPv4ToIPv6(netip.MustParseAddr("192.168.255.1"))
	if err != nil || v6 != r.Xlate.LocalAddr6 {
		t.Errorf("self map %s %v", v6, err)
	}
}

func joinPrefixes(rs []netconf.Route) string {
	var s []string
	for _, r := range rs {
		s = append(s, r.Prefix.String())
	}
	// stable order for comparison
	for i := range s {
		for j := i + 1; j < len(s); j++ {
			if s[j] < s[i] {
				s[i], s[j] = s[j], s[i]
			}
		}
	}
	return strings.Join(s, " ")
}

func TestUnknownFieldRejected(t *testing.T) {
	var cfg Config
	if err := LoadYAML(&cfg, []byte("ipv4_addr: 1.2.3.4\n")); err == nil {
		t.Fatal("expected error for unknown field")
	}
}

func TestEnvOverrides(t *testing.T) {
	env := map[string]string{
		"CLATTO_IPV4_ADDRESS":        "192.0.0.2",
		"CLATTO_IPV6_ADDRESS":        "2001:db8::c1a7",
		"CLATTO_PREFIX":              "64:ff9b::/96",
		"CLATTO_MAPS":                "192.0.0.1=2001:db8::464, 10.0.0.0/24=2001:db8:a::/120",
		"CLATTO_INTERFACE":           "clat",
		"CLATTO_WKPF_STRICT":         "no",
		"CLATTO_LOG_PACKETS":         "drop reject",
		"CLATTO_INTERFACE_ROUTES":    "0.0.0.0/0",
		"CLATTO_DYNAMIC_POOL":        "100.64.0.0/24",
		"STATE_DIRECTORY":            "/var/lib/clatto:/other",
		"CLATTO_HTTP_LISTEN":         "off",
		"CLATTO_INTERFACE_ADDRESSES": "192.0.0.1",
	}
	var cfg Config
	if err := LoadEnv(&cfg, func(k string) (string, bool) { v, ok := env[k]; return v, ok }); err != nil {
		t.Fatal(err)
	}
	r, err := Resolve(cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	if r.Config.Interface.Name != "clat" || len(r.Config.Maps) != 2 || r.Config.Maps[1].IPv6 != "2001:db8:a::/120" {
		t.Errorf("%+v", r.Config)
	}
	if r.Config.DynamicPool.StateFile != "/var/lib/clatto/dynamic.map" {
		t.Errorf("state file %q", r.Config.DynamicPool.StateFile)
	}
	if r.HTTPListen != "" {
		t.Errorf("http should be off")
	}
	if len(r.Config.Interface.Addresses) != 1 || r.Config.Interface.Addresses[0].Bits() != 32 {
		t.Errorf("addresses %v", r.Config.Interface.Addresses)
	}
	found := false
	for _, rt := range r.Routes4 {
		if rt.Prefix.Bits() == 0 {
			found = true
		}
	}
	if !found {
		t.Errorf("default route missing from %v", r.Routes4)
	}
	// Private address through the well-known prefix is fine when not strict.
	if _, err := r.Table.MapIPv4ToIPv6(netip.MustParseAddr("10.9.9.9")); err != nil {
		t.Errorf("wkpf lenient: %v", err)
	}
}

func TestResolveErrors(t *testing.T) {
	cases := map[string]string{
		"no maps":          "ipv4_address: 192.168.255.1\n",
		"no ipv4":          "prefix: 64:ff9b::/96\n",
		"wkpf private":     "ipv4_address: 192.168.255.1\nprefix: 64:ff9b::/96\n",
		"v6 inside prefix": "ipv4_address: 192.168.255.1\nipv6_address: 2001:db8::1\nprefix: 2001:db8::/96\n",
		"bad prefix len":   "ipv4_address: 192.168.255.1\nprefix: 2001:db8::/80\n",
		"small mtu":        "ipv4_address: 192.168.255.1\nprefix: 2001:db8::/96\ninterface: {mtu: 1000}\n",
		"bad udp":          "ipv4_address: 192.168.255.1\nprefix: 2001:db8::/96\nudp_checksum: maybe\n",
		"pool too big":     "ipv4_address: 192.168.255.1\nprefix: 2001:db8::/96\ndynamic_pool: {prefix: 10.0.0.0/7}\n",
		"relative state":   "ipv4_address: 192.168.255.1\nprefix: 2001:db8::/96\ndynamic_pool: {prefix: 10.0.0.0/24, state_file: x.map}\n",
	}
	for name, y := range cases {
		var cfg Config
		if err := LoadYAML(&cfg, []byte(y)); err != nil {
			t.Fatalf("%s: yaml: %v", name, err)
		}
		if _, err := Resolve(cfg, nil); err == nil {
			t.Errorf("%s: expected error", name)
		}
	}
}

func TestClatExample(t *testing.T) {
	// A CLAT with a dedicated address: the clat block with the address
	// given instead of detected.
	y := `
prefix: 64:ff9b::/96
clat:
  ipv6_address: 2001:db8::464
`
	var cfg Config
	if err := LoadYAML(&cfg, []byte(y)); err != nil {
		t.Fatal(err)
	}
	r, err := Resolve(cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := joinPrefixes(r.Routes4), "0.0.0.0/0 192.0.0.2/32"; got != want {
		t.Errorf("routes4 %q want %q", got, want)
	}
	// Neither the prefix nor the CLAT address goes into the device via
	// the main table: the PLAT is reached over the network and replies
	// enter through the policy rule.
	if len(r.Routes6) != 0 {
		t.Errorf("routes6 %+v want none", r.Routes6)
	}
	if r.Shared == nil || r.Shared.Addr != netip.MustParseAddr("2001:db8::464") {
		t.Errorf("shared %+v", r.Shared)
	}
	v6, err := r.Table.MapIPv4ToIPv6(netip.MustParseAddr("192.0.0.1"))
	if err != nil || v6 != netip.MustParseAddr("2001:db8::464") {
		t.Errorf("clat map: %s %v", v6, err)
	}
	v6, err = r.Table.MapIPv4ToIPv6(netip.MustParseAddr("8.8.8.8"))
	if err != nil || v6 != netip.MustParseAddr("64:ff9b::8.8.8.8") {
		t.Errorf("plat map: %s %v", v6, err)
	}
}

func fakeSource(dst netip.Addr) (netip.Addr, error) {
	if dst != netip.MustParseAddr("64:ff9b::") {
		return netip.Addr{}, fmt.Errorf("unexpected lookup for %s", dst)
	}
	return netip.MustParseAddr("2001:db8:cafe::7"), nil
}

func TestCLATShared(t *testing.T) {
	y := `
prefix: 64:ff9b::/96
clat:
  ports: [tcp/61000-61099, udp/5000, icmp]
interface:
  routes:
    - {prefix: 0.0.0.0/0, metric: 2048, mtu: 1260, advmss: 1220}
`
	var cfg Config
	if err := LoadYAML(&cfg, []byte(y)); err != nil {
		t.Fatal(err)
	}
	r, err := ResolveWith(cfg, ResolveOptions{SourceAddr: fakeSource})
	if err != nil {
		t.Fatal(err)
	}
	pod := netip.MustParseAddr("2001:db8:cafe::7")
	if cfg.CLAT.IPv6Address != "" {
		t.Errorf("caller's config mutated: %+v", cfg.CLAT)
	}
	if c := r.Config.CLAT; c.IPv6Address != pod.String() || c.IPv4Address != DefaultCLATHostIPv4 || c.Table != DefaultCLATTable {
		t.Errorf("clat block %+v", c)
	}
	if r.Config.IPv4Address != DefaultCLATTranslatorIPv4 || r.Xlate.LocalAddr6 != netip.MustParseAddr("64:ff9b::192.0.0.2") {
		t.Errorf("translator addresses %s %s", r.Config.IPv4Address, r.Xlate.LocalAddr6)
	}
	if v6, err := r.Table.MapIPv4ToIPv6(DefaultCLATHostIPv4); err != nil || v6 != pod {
		t.Errorf("host map %s %v", v6, err)
	}
	if v4, err := r.Table.MapIPv6ToIPv4(pod, false); err != nil || v4 != DefaultCLATHostIPv4 {
		t.Errorf("host map back %s %v", v4, err)
	}
	if len(r.Addresses) != 1 || r.Addresses[0] != netip.MustParsePrefix("192.0.0.1/32") {
		t.Errorf("addresses %v", r.Addresses)
	}
	want4 := []netconf.Route{
		{Prefix: netip.MustParsePrefix("0.0.0.0/0"), Metric: 2048, MTU: 1260, AdvMSS: 1220},
		{Prefix: netip.MustParsePrefix("192.0.0.2/32")},
	}
	if !reflect.DeepEqual(r.Routes4, want4) {
		t.Errorf("routes4 %+v want %+v", r.Routes4, want4)
	}
	if len(r.Routes6) != 0 {
		t.Errorf("routes6 %+v, want none in CLAT mode", r.Routes6)
	}
	wantShared := &netconf.Shared{Addr: pod, From: netip.MustParsePrefix("64:ff9b::/96"), Table: 0xc1a7, Filters: []netconf.Filter{
		{Proto: 6, Start: 61000, End: 61099}, {Proto: 17, Start: 5000, End: 5000}, {Proto: 58},
	}}
	if !reflect.DeepEqual(r.Shared, wantShared) {
		t.Errorf("shared %+v want %+v", r.Shared, wantShared)
	}
	if r.Forward4() || !r.Forward6() {
		t.Errorf("forwarding: v4 %v v6 %v", r.Forward4(), r.Forward6())
	}
	// PLAT traffic still embeds; the shared address is a static map.
	if v6, err := r.Table.MapIPv4ToIPv6(netip.MustParseAddr("1.1.1.1")); err != nil || v6 != netip.MustParseAddr("64:ff9b::1.1.1.1") {
		t.Errorf("plat map %s %v", v6, err)
	}
	// The effective configuration shows the detected address and the
	// route options, and loads back.
	data, err := Marshal(r.Config)
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range []string{"ipv6_address: 2001:db8:cafe::7", "prefix: 0.0.0.0/0", "advmss: 1220", "- tcp/61000-61099"} {
		if !strings.Contains(string(data), s) {
			t.Errorf("marshalled config lacks %q:\n%s", s, data)
		}
	}
	var back Config
	if err := LoadYAML(&back, data); err != nil {
		t.Fatalf("reload marshalled config: %v\n%s", err, data)
	}
	if _, err := ResolveWith(back, ResolveOptions{}); err != nil {
		t.Errorf("resolve marshalled config without auto: %v", err)
	}
}

func TestCLATDefaultsAndEnv(t *testing.T) {
	env := map[string]string{
		"CLATTO_PREFIX":            "64:ff9b::/96",
		"CLATTO_CLAT_IPV6_ADDRESS": "2001:db8::42",
		"CLATTO_CLAT_PORTS":        "udp/61000-61099 tcp/443",
		"CLATTO_CLAT_TABLE":        "0x64",
		"CLATTO_INTERFACE_SYSCTL":  "false",
	}
	var cfg Config
	if err := LoadEnv(&cfg, func(k string) (string, bool) { v, ok := env[k]; return v, ok }); err != nil {
		t.Fatal(err)
	}
	r, err := Resolve(cfg, nil) // no SourceAddr needed: the address is explicit
	if err != nil {
		t.Fatal(err)
	}
	if r.Shared == nil || r.Shared.Addr != netip.MustParseAddr("2001:db8::42") || r.Shared.Table != 100 || len(r.Shared.Filters) != 2 {
		t.Errorf("shared %+v", r.Shared)
	}
	if got := joinPrefixes(r.Routes4); got != "0.0.0.0/0 192.0.0.2/32" {
		t.Errorf("routes4 %q", got)
	}
	if r.Forward6() {
		t.Error("sysctl disabled but Forward6 set")
	}
	// CLATTO_CLAT=true alone enables the block with auto detection.
	env = map[string]string{"CLATTO_PREFIX": "64:ff9b::/96", "CLATTO_CLAT": "true"}
	cfg = Config{}
	if err := LoadEnv(&cfg, func(k string) (string, bool) { v, ok := env[k]; return v, ok }); err != nil {
		t.Fatal(err)
	}
	if cfg.CLAT == nil {
		t.Fatal("CLATTO_CLAT=true did not enable the block")
	}
	if _, err := Resolve(cfg, nil); err == nil || !strings.Contains(err.Error(), "automatic detection") {
		t.Errorf("auto without a resolver: %v", err)
	}
	if _, err := ResolveWith(cfg, ResolveOptions{SourceAddr: fakeSource}); err != nil {
		t.Errorf("auto with a resolver: %v", err)
	}
}

func TestCLATErrors(t *testing.T) {
	cases := map[string]string{
		"no prefix":          "clat: {ipv6_address: 2001:db8::1}\n",
		"inside prefix":      "prefix: 64:ff9b::/96\nclat: {ipv6_address: 64:ff9b::1}\n",
		"not ipv6":           "prefix: 64:ff9b::/96\nclat: {ipv6_address: 10.0.0.1}\n",
		"bad port proto":     "prefix: 64:ff9b::/96\nclat: {ipv6_address: 2001:db8::1, ports: [gre/1]}\n",
		"reversed range":     "prefix: 64:ff9b::/96\nclat: {ipv6_address: 2001:db8::1, ports: [tcp/20-10]}\n",
		"icmp with ports":    "prefix: 64:ff9b::/96\nclat: {ipv6_address: 2001:db8::1, ports: [icmp/1]}\n",
		"reserved table":     "prefix: 64:ff9b::/96\nclat: {ipv6_address: 2001:db8::1, table: 255}\n",
		"same as translator": "prefix: 64:ff9b::/96\nipv4_address: 192.0.0.1\nclat: {ipv6_address: 2001:db8::1}\n",
		"route no prefix":    "prefix: 64:ff9b::/96\nclat: {ipv6_address: 2001:db8::1}\ninterface: {routes: [{metric: 1}]}\n",
		"route bad field":    "prefix: 64:ff9b::/96\nclat: {ipv6_address: 2001:db8::1}\ninterface: {routes: [{prefix: 0.0.0.0/0, hops: 1}]}\n",
	}
	for name, y := range cases {
		var cfg Config
		err := LoadYAML(&cfg, []byte(y))
		if err == nil {
			_, err = Resolve(cfg, nil)
		}
		if err == nil {
			t.Errorf("%s: expected error", name)
		}
	}
}

func TestParseFilter(t *testing.T) {
	good := map[string]netconf.Filter{
		"tcp":          {Proto: 6},
		"udp/53":       {Proto: 17, Start: 53, End: 53},
		"TCP/1-65535":  {Proto: 6, Start: 1, End: 65535},
		"sctp/100-200": {Proto: 132, Start: 100, End: 200},
		"icmp":         {Proto: 58},
		"ipv6-icmp":    {Proto: 58},
	}
	for s, want := range good {
		got, err := ParseFilter(s)
		if err != nil || got != want {
			t.Errorf("%q: %+v %v, want %+v", s, got, err, want)
		}
	}
	for _, s := range []string{"", "tcp/", "tcp/0", "tcp/65536", "tcp/a-b", "udp/10-", "6/1"} {
		if _, err := ParseFilter(s); err == nil {
			t.Errorf("%q: expected error", s)
		}
	}
}

// TestAutoRoutesReceiveOnly checks that automatic routes cover only what
// the translator must receive. Routing the IPv6 side of a static map
// into the interface sends translated packets straight back into the
// translator until their hop limit expires.
func TestAutoRoutesReceiveOnly(t *testing.T) {
	y := `
ipv4_address: 172.18.0.3
ipv6_address: 2001:db8:ffff::3
prefix: 64:ff9b::/96
wkpf_strict: false
maps:
  - {ipv4: 172.18.0.1, ipv6: 2001:db8:3500::100}
  - {ipv4: 172.18.0.2, ipv6: 2001:db8:3500::443}
dynamic_pool: {prefix: 172.18.0.128/25}
`
	var cfg Config
	if err := LoadYAML(&cfg, []byte(y)); err != nil {
		t.Fatal(err)
	}
	r, err := Resolve(cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := joinPrefixes(r.Routes4), "172.18.0.1/32 172.18.0.128/25 172.18.0.2/32 172.18.0.3/32"; got != want {
		t.Errorf("routes4 %q want %q", got, want)
	}
	// The prefix and the translator's own explicit address, nothing else.
	if got, want := joinPrefixes(r.Routes6), "2001:db8:ffff::3/128 64:ff9b::/96"; got != want {
		t.Errorf("routes6 %q want %q", got, want)
	}
}
