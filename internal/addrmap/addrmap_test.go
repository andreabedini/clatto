package addrmap

import (
	"errors"
	"net/netip"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/andreabedini/clatto/internal/xlate"
)

func mustBuild(t *testing.T, b *Builder) *Table {
	t.Helper()
	tab, err := b.Build()
	if err != nil {
		t.Fatal(err)
	}
	return tab
}

func addr(s string) netip.Addr     { return netip.MustParseAddr(s) }
func prefix(s string) netip.Prefix { return netip.MustParsePrefix(s) }

func TestStaticAndPrefix(t *testing.T) {
	b := NewBuilder(true)
	if err := b.AddPrefix(prefix("2001:db8:1:ffff::/96")); err != nil {
		t.Fatal(err)
	}
	if err := b.AddStatic(prefix("192.168.255.1/32"), prefix("2001:db8::1/128")); err != nil {
		t.Fatal(err)
	}
	if err := b.AddStatic(prefix("10.1.0.0/24"), prefix("2001:db8:1:4444::/120")); err != nil {
		t.Fatal(err)
	}
	tab := mustBuild(t, b)

	got, err := tab.MapIPv4ToIPv6(addr("192.168.255.1"))
	if err != nil || got != addr("2001:db8::1") {
		t.Errorf("host map: %s %v", got, err)
	}
	got, err = tab.MapIPv4ToIPv6(addr("10.1.0.42"))
	if err != nil || got != addr("2001:db8:1:4444::2a") {
		t.Errorf("net map: %s %v", got, err)
	}
	got4, err := tab.MapIPv6ToIPv4(addr("2001:db8:1:4444::2a"), false)
	if err != nil || got4 != addr("10.1.0.42") {
		t.Errorf("net map back: %s %v", got4, err)
	}
	got, err = tab.MapIPv4ToIPv6(addr("198.51.100.7"))
	if err != nil || got != addr("2001:db8:1:ffff::198.51.100.7") {
		t.Errorf("prefix map: %s %v", got, err)
	}
	got4, err = tab.MapIPv6ToIPv4(addr("2001:db8:1:ffff::198.51.100.7"), false)
	if err != nil || got4 != addr("198.51.100.7") {
		t.Errorf("prefix map back: %s %v", got4, err)
	}
	// Hairpin: statically mapped address reached through the prefix.
	if _, err := tab.MapIPv6ToIPv4(addr("2001:db8:1:ffff::192.168.255.1"), false); !errors.Is(err, xlate.ErrDrop) {
		t.Errorf("hairpin: %v", err)
	}
	// Unknown IPv6 host with no pool.
	if _, err := tab.MapIPv6ToIPv4(addr("2001:db8:9::1"), true); !errors.Is(err, xlate.ErrReject) {
		t.Errorf("unknown: %v", err)
	}
	// Reserved IPv4 through the prefix.
	if _, err := tab.MapIPv4ToIPv6(addr("127.0.0.1")); !errors.Is(err, xlate.ErrDrop) {
		t.Errorf("loopback: %v", err)
	}
	if _, err := tab.MapIPv4ToIPv6(addr("169.254.1.1")); !errors.Is(err, xlate.ErrDrop) {
		t.Errorf("link-local: %v", err)
	}
}

func TestWellKnownPrefixStrict(t *testing.T) {
	for _, strict := range []bool{true, false} {
		b := NewBuilder(strict)
		if err := b.AddPrefix(prefix("64:ff9b::/96")); err != nil {
			t.Fatal(err)
		}
		tab := mustBuild(t, b)
		_, err := tab.MapIPv4ToIPv6(addr("10.0.0.1"))
		if strict && !errors.Is(err, xlate.ErrReject) {
			t.Errorf("strict: private should be rejected, got %v", err)
		}
		if !strict && err != nil {
			t.Errorf("lenient: %v", err)
		}
		_, err = tab.MapIPv6ToIPv4(addr("64:ff9b::10.0.0.1"), false)
		if strict && !errors.Is(err, xlate.ErrReject) {
			t.Errorf("strict back: %v", err)
		}
	}
}

func TestConflicts(t *testing.T) {
	b := NewBuilder(true)
	_ = b.AddPrefix(prefix("2001:db8:1:ffff::/96"))
	_ = b.AddStatic(prefix("192.168.1.1/32"), prefix("2001:db8:1:ffff::1/128"))
	if _, err := b.Build(); !errors.Is(err, ErrConflict) {
		t.Errorf("static inside prefix: %v", err)
	}
	b = NewBuilder(true)
	_ = b.AddStatic(prefix("192.168.1.1/32"), prefix("2001:db8::1/128"))
	_ = b.AddStatic(prefix("192.168.1.1/32"), prefix("2001:db8::2/128"))
	if _, err := b.Build(); !errors.Is(err, ErrConflict) {
		t.Errorf("duplicate v4: %v", err)
	}
	b = NewBuilder(true)
	_ = b.AddStatic(prefix("192.168.1.0/24"), prefix("2001:db8::/120"))
	_ = b.AddStatic(prefix("192.168.2.0/24"), prefix("2001:db8::/120"))
	if _, err := b.Build(); !errors.Is(err, ErrConflict) {
		t.Errorf("duplicate v6: %v", err)
	}
	if err := b.AddPrefix(prefix("2001:db8::/50")); err == nil {
		t.Errorf("bad prefix length accepted")
	}
	if err := b.AddStatic(prefix("192.168.1.0/24"), prefix("2001:db8::/124")); err == nil {
		t.Errorf("mismatched sizes accepted")
	}
}

func TestEmbeddedSizes(t *testing.T) {
	for _, n := range []int{32, 40, 48, 56, 64, 96} {
		b := NewBuilder(true)
		p := netip.PrefixFrom(addr("2001:db8::"), n)
		if err := b.AddPrefix(p); err != nil {
			t.Fatal(err)
		}
		tab := mustBuild(t, b)
		v6, err := tab.MapIPv4ToIPv6(addr("192.0.2.33"))
		if err != nil {
			t.Fatal(err)
		}
		v4, err := tab.MapIPv6ToIPv4(v6, false)
		if err != nil || v4 != addr("192.0.2.33") {
			t.Errorf("/%d: %s -> %s %v", n, v6, v4, err)
		}
	}
}

type dynRecorder struct{ reasons []xlate.Reason }

func (r *dynRecorder) Translated(uint8, int) {}
func (r *dynRecorder) Event(e xlate.Event)   { r.reasons = append(r.reasons, e.Reason) }

func newPoolTable(t *testing.T, clock *time.Time, rec xlate.Observer) (*Table, *Pool) {
	t.Helper()
	pool, err := NewPool(prefix("192.168.255.0/29"), PoolOptions{Now: func() time.Time { return *clock }, Observer: rec})
	if err != nil {
		t.Fatal(err)
	}
	b := NewBuilder(true)
	_ = b.AddPrefix(prefix("2001:db8:1:ffff::/96"))
	// The translator's own address sits inside the pool and must be skipped.
	_ = b.AddStatic(prefix("192.168.255.1/32"), prefix("2001:db8::1/128"))
	if err := b.SetPool(pool); err != nil {
		t.Fatal(err)
	}
	return mustBuild(t, b), pool
}

func TestDynamicPool(t *testing.T) {
	clock := time.Unix(1_700_000_000, 0)
	rec := &dynRecorder{}
	tab, pool := newPoolTable(t, &clock, rec)

	// /29 has 7 usable offsets minus .1 which is static: 6 addresses.
	hosts := make([]netip.Addr, 0, 6)
	seen := map[netip.Addr]bool{}
	for i := 0; i < 6; i++ {
		h := netip.MustParseAddr("2001:db8:2::" + string(rune('a'+i)))
		v4, err := tab.MapIPv6ToIPv4(h, true)
		if err != nil {
			t.Fatalf("host %d: %v", i, err)
		}
		if !pool.Prefix().Contains(v4) || v4 == addr("192.168.255.0") || v4 == addr("192.168.255.1") {
			t.Fatalf("host %d got %s", i, v4)
		}
		if seen[v4] {
			t.Fatalf("address %s handed out twice", v4)
		}
		seen[v4] = true
		hosts = append(hosts, h)
		// Reverse direction works and is stable.
		back, err := tab.MapIPv4ToIPv6(v4)
		if err != nil || back != h {
			t.Fatalf("reverse: %s %v", back, err)
		}
		again, _ := tab.MapIPv6ToIPv4(h, true)
		if again != v4 {
			t.Fatalf("unstable assignment")
		}
	}
	if s := pool.Stats(); s.Mapped != 6 || s.Dormant != 0 || pool.usedCount() != 6 {
		t.Fatalf("stats %+v used %d", s, pool.usedCount())
	}
	// Seventh host: exhausted, nothing dormant to steal.
	if _, err := tab.MapIPv6ToIPv4(addr("2001:db8:2::99"), true); !errors.Is(err, xlate.ErrReject) {
		t.Fatalf("expected reject when exhausted, got %v", err)
	}
	// Without allocate, unknown hosts are rejected.
	if _, err := tab.MapIPv6ToIPv4(addr("2001:db8:2::98"), false); !errors.Is(err, xlate.ErrReject) {
		t.Fatalf("expected reject without allocate")
	}

	// Let host 0 go idle past the minimum lease; it becomes dormant and its
	// IPv4 address stops mapping back, but a returning packet reactivates it.
	first4, _ := tab.MapIPv6ToIPv4(hosts[0], false)
	clock = clock.Add(DefaultMinLease + time.Minute)
	for _, h := range hosts[1:] {
		tab.MapIPv6ToIPv4(h, false) // keep the others fresh
	}
	pool.Maintain()
	if s := pool.Stats(); s.Mapped != 5 || s.Dormant != 1 {
		t.Fatalf("after maint: %+v", s)
	}
	if _, err := tab.MapIPv4ToIPv6(first4); !errors.Is(err, xlate.ErrReject) {
		t.Fatalf("dormant address still maps: %v", err)
	}
	// Now a new host can steal the dormant slot.
	newHost := addr("2001:db8:2::99")
	v4, err := tab.MapIPv6ToIPv4(newHost, true)
	if err != nil || v4 != first4 {
		t.Fatalf("steal: %s %v (want %s)", v4, err, first4)
	}
	// And the original host, coming back, gets a reject (nothing left).
	if _, err := tab.MapIPv6ToIPv4(hosts[0], true); !errors.Is(err, xlate.ErrReject) {
		t.Fatalf("expected reject for evicted host, got %v", err)
	}
	// Release after max lease.
	clock = clock.Add(DefaultMaxLease + time.Minute)
	pool.Maintain() // everything dormant
	clock = clock.Add(DefaultMaxLease + time.Minute)
	pool.Maintain() // everything released
	if s := pool.Stats(); s.Mapped != 0 || s.Dormant != 0 || pool.usedCount() != 0 {
		t.Fatalf("after release: %+v used %d", s, pool.usedCount())
	}
	want := []xlate.Reason{xlate.ReasonDynamicAssigned, xlate.ReasonDynamicExhausted, xlate.ReasonDynamicDormant, xlate.ReasonDynamicReassigned, xlate.ReasonDynamicReleased}
	for _, w := range want {
		found := false
		for _, r := range rec.reasons {
			if r == w {
				found = true
			}
		}
		if !found {
			t.Errorf("no %s event", w)
		}
	}
}

func TestPoolSaveLoad(t *testing.T) {
	clock := time.Unix(1_700_000_000, 0)
	tab, pool := newPoolTable(t, &clock, nil)
	a, _ := tab.MapIPv6ToIPv4(addr("2001:db8:2::a"), true)
	b, _ := tab.MapIPv6ToIPv4(addr("2001:db8:2::b"), true)
	path := filepath.Join(t.TempDir(), "dynamic.map")
	if !pool.Dirty() {
		t.Fatal("expected dirty")
	}
	if err := pool.Save(path); err != nil {
		t.Fatal(err)
	}
	if pool.Dirty() {
		t.Fatal("expected clean after save")
	}

	// Reload into a fresh table 10 minutes later: both mapped.
	clock = clock.Add(10 * time.Minute)
	tab2, pool2 := newPoolTable(t, &clock, nil)
	n, err := pool2.Load(path)
	if err != nil || n != 2 {
		t.Fatalf("load: %d %v", n, err)
	}
	if got, _ := tab2.MapIPv6ToIPv4(addr("2001:db8:2::a"), false); got != a {
		t.Errorf("host a: %s want %s", got, a)
	}
	if got, _ := tab2.MapIPv4ToIPv6(b); got != addr("2001:db8:2::b") {
		t.Errorf("host b reverse: %s", got)
	}

	// Reload a day later: dormant, reactivated on demand with same address.
	clock = clock.Add(24 * time.Hour)
	tab3, pool3 := newPoolTable(t, &clock, nil)
	if _, err := pool3.Load(path); err != nil {
		t.Fatal(err)
	}
	if s := pool3.Stats(); s.Mapped != 0 || s.Dormant != 2 {
		t.Fatalf("stats %+v", s)
	}
	if got, _ := tab3.MapIPv6ToIPv4(addr("2001:db8:2::a"), true); got != a {
		t.Errorf("reactivated a: %s want %s", got, a)
	}

	// tayga-format lines with tabs and comments are accepted.
	tab4, pool4 := newPoolTable(t, &clock, nil)
	r := strings.NewReader("### tayga dynamic map database\n\n192.168.255.5\t2001:db8:2::f\t" + "1700000000" + "\nbogus line\n")
	if n, err := pool4.read(r); err != nil || n != 1 {
		t.Fatalf("read: %d %v", n, err)
	}
	if got, _ := tab4.MapIPv6ToIPv4(addr("2001:db8:2::f"), true); got != addr("192.168.255.5") {
		t.Errorf("tayga entry: %s", got)
	}
}
