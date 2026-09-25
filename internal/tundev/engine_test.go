package tundev

import (
	"context"
	"encoding/binary"
	"log/slog"
	"net/netip"
	"testing"
	"time"

	"github.com/andreabedini/clatto/internal/addrmap"
	"github.com/andreabedini/clatto/internal/xlate"
)

func TestEnginePipeline(t *testing.T) {
	b := addrmap.NewBuilder(true)
	if err := b.AddPrefix(netip.MustParsePrefix("64:ff9b::/96")); err != nil {
		t.Fatal(err)
	}
	if err := b.AddStatic(netip.MustParsePrefix("192.0.2.10/32"), netip.MustParsePrefix("2001:db8::10/128")); err != nil {
		t.Fatal(err)
	}
	if err := b.AddSelf(netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("2001:db8::1"), false); err != nil {
		t.Fatal(err)
	}
	table, err := b.Build()
	if err != nil {
		t.Fatal(err)
	}
	tr := xlate.New(xlate.Config{
		LocalAddr4: netip.MustParseAddr("192.0.2.1"),
		LocalAddr6: netip.MustParseAddr("2001:db8::1"),
		MTU:        1500,
	}, table, nil)

	dev := NewFakeDevice(8, 1500)
	eng := NewEngine(dev, tr, slog.Default())
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- eng.Run(ctx) }()

	// IPv6 UDP from the mapped host to an IPv4 destination through the prefix.
	payload := []byte("hello")
	udp := make([]byte, 8+len(payload))
	binary.BigEndian.PutUint16(udp[0:], 1111)
	binary.BigEndian.PutUint16(udp[2:], 2222)
	binary.BigEndian.PutUint16(udp[4:], uint16(len(udp)))
	copy(udp[8:], payload)
	binary.BigEndian.PutUint16(udp[6:], 0xffff) // any non-zero value; adjusted incrementally
	pkt := make([]byte, 40+len(udp))
	pkt[0] = 0x60
	binary.BigEndian.PutUint16(pkt[4:], uint16(len(udp)))
	pkt[6] = 17
	pkt[7] = 64
	src := netip.MustParseAddr("2001:db8::10").As16()
	dst := netip.MustParseAddr("64:ff9b::8.8.8.8").As16()
	copy(pkt[8:], src[:])
	copy(pkt[24:], dst[:])
	copy(pkt[40:], udp)

	for i := 0; i < 3; i++ {
		dev.Inject(pkt)
	}
	for i := 0; i < 3; i++ {
		select {
		case out := <-dev.Out:
			if out[0]>>4 != 4 || out[9] != 17 || len(out) != 20+len(udp) {
				t.Fatalf("unexpected output %x", out)
			}
			if s := netip.AddrFrom4([4]byte(out[12:16])); s != netip.MustParseAddr("192.0.2.10") {
				t.Fatalf("src %s", s)
			}
			if d := netip.AddrFrom4([4]byte(out[16:20])); d != netip.MustParseAddr("8.8.8.8") {
				t.Fatalf("dst %s", d)
			}
		case <-time.After(2 * time.Second):
			t.Fatal("timeout waiting for output")
		}
	}
	// Swapping the translator takes effect.
	eng.SetTranslator(xlate.New(xlate.Config{LocalAddr4: netip.MustParseAddr("192.0.2.1"), LocalAddr6: netip.MustParseAddr("2001:db8::1"), MTU: 1500}, addrmapEmpty(t), nil))
	dev.Inject(pkt)
	select {
	case out := <-dev.Out:
		if out[0]>>4 != 6 || out[6] != 58 || out[40] != 1 {
			t.Fatalf("expected ICMPv6 unreachable, got %x", out[:48])
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timeout")
	}
	st := eng.Stats()
	if st.PacketsIn != 4 || st.PacketsOut != 4 {
		t.Errorf("stats %+v", st)
	}
	cancel()
	if err := <-done; err != nil && err != context.Canceled {
		t.Fatal(err)
	}
}

func addrmapEmpty(t *testing.T) *addrmap.Table {
	b := addrmap.NewBuilder(true)
	if err := b.AddStatic(netip.MustParsePrefix("192.0.2.1/32"), netip.MustParsePrefix("2001:db8::1/128")); err != nil {
		t.Fatal(err)
	}
	tab, err := b.Build()
	if err != nil {
		t.Fatal(err)
	}
	return tab
}
