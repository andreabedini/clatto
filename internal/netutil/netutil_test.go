package netutil

import (
	"net/netip"
	"testing"
)

func TestEmbedExtractRoundTrip(t *testing.T) {
	// Examples from RFC 6052 section 2.4, prefix 2001:db8::/n, IPv4 192.0.2.33.
	cases := map[int]string{
		32: "2001:db8:c000:221::",
		40: "2001:db8:1c0:2:21::",
		48: "2001:db8:122:c000:2:2100::",
		56: "2001:db8:122:3c0:0:221::",
		64: "2001:db8:122:344:c0:2:2100::",
		96: "2001:db8:122:344::192.0.2.33",
	}
	prefixes := map[int]string{
		32: "2001:db8::/32",
		40: "2001:db8:100::/40",
		48: "2001:db8:122::/48",
		56: "2001:db8:122:300::/56",
		64: "2001:db8:122:344::/64",
		96: "2001:db8:122:344::/96",
	}
	v4 := netip.MustParseAddr("192.0.2.33").As4()
	for n, want := range cases {
		p := netip.MustParsePrefix(prefixes[n])
		got, err := Embed(p.Addr().As16(), n, v4)
		if err != nil {
			t.Fatalf("/%d: %v", n, err)
		}
		if g := netip.AddrFrom16(got); g != netip.MustParseAddr(want) {
			t.Errorf("/%d: embed = %s, want %s", n, g, want)
		}
		back, err := Extract(got, n)
		if err != nil || back != v4 {
			t.Errorf("/%d: extract = %v, %v", n, back, err)
		}
	}
}

func TestExtractRejectsNonZeroU(t *testing.T) {
	a := netip.MustParseAddr("2001:db8:1c0:2:ff21::").As16()
	if _, err := Extract(a, 40); err == nil {
		t.Fatal("expected error for non-zero u octet")
	}
}

func TestClassifyIPv4(t *testing.T) {
	cases := map[string]IPv4Class{
		"0.1.2.3":         IPv4Invalid,
		"127.0.0.1":       IPv4Invalid,
		"169.254.1.1":     IPv4LinkLocal,
		"224.0.0.1":       IPv4Invalid,
		"255.255.255.255": IPv4Invalid,
		"240.0.0.1":       IPv4Valid,
		"192.0.2.1":       IPv4Valid,
	}
	for s, want := range cases {
		if got := ClassifyIPv4(netip.MustParseAddr(s).As4()); got != want {
			t.Errorf("%s: got %v want %v", s, got, want)
		}
	}
}

func TestValidIPv6(t *testing.T) {
	cases := map[string]bool{
		"64:ff9b::1":   true,
		"::1":          false,
		"ff02::1":      false,
		"fe80::1":      false,
		"2001:db8::1":  true,
		"fec0::1":      true,
		"64:ff9b:1::1": true,
	}
	for s, want := range cases {
		if got := ValidIPv6(netip.MustParseAddr(s).As16()); got != want {
			t.Errorf("%s: got %v want %v", s, got, want)
		}
	}
}
