package config

import (
	"net/netip"
	"strings"
	"testing"

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
	want6 := "2001:db8:1:4444::1/128 2001:db8:1:5555::/120 2001:db8:1:ffff::/96"
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

func joinPrefixes(ps []netip.Prefix) string {
	var s []string
	for _, p := range ps {
		s = append(s, p.String())
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
	for _, p := range r.Routes4 {
		if p.Bits() == 0 {
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
	// A CLAT: the host's IPv4 address maps to a dedicated IPv6 address, the
	// PLAT prefix is the well-known one.
	y := `
ipv4_address: 192.0.0.2
ipv6_address: 2001:db8::c1a7
prefix: 64:ff9b::/96
maps:
  - ipv4: 192.0.0.1
    ipv6: 2001:db8::464
interface:
  addresses: [192.0.0.1/32]
  routes: [0.0.0.0/0]
`
	var cfg Config
	if err := LoadYAML(&cfg, []byte(y)); err != nil {
		t.Fatal(err)
	}
	r, err := Resolve(cfg, nil)
	if err != nil {
		t.Fatal(err)
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
