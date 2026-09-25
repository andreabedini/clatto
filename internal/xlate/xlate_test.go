package xlate

import (
	"bytes"
	"encoding/binary"
	"net/netip"
	"testing"

	"github.com/andreabedini/clatto/internal/netutil"
)

// testMapper embeds in 64:ff9b::/96 with a couple of static host maps.
type testMapper struct {
	static4 map[netip.Addr]netip.Addr
	static6 map[netip.Addr]netip.Addr
	reject4 map[netip.Addr]bool
}

var (
	local4  = netip.MustParseAddr("192.168.255.1")
	local6  = netip.MustParseAddr("2001:db8::1")
	host4   = netip.MustParseAddr("192.168.255.2") // static map of host6
	host6   = netip.MustParseAddr("2001:db8:1::2")
	remote4 = netip.MustParseAddr("198.51.100.7")
	remote6 = netip.MustParseAddr("64:ff9b::198.51.100.7")
	unmap6  = netip.MustParseAddr("2001:db8:ffff::9")
	prefix  = netutil.WellKnownPrefix
)

func newTestMapper() *testMapper {
	m := &testMapper{
		static4: map[netip.Addr]netip.Addr{local4: local6, host4: host6},
		static6: map[netip.Addr]netip.Addr{local6: local4, host6: host4},
		reject4: map[netip.Addr]bool{},
	}
	return m
}

func (m *testMapper) MapIPv4ToIPv6(a netip.Addr) (netip.Addr, error) {
	if m.reject4[a] {
		return netip.Addr{}, ErrReject
	}
	if r, ok := m.static4[a]; ok {
		return r, nil
	}
	if netutil.ClassifyIPv4(a.As4()) != netutil.IPv4Valid {
		return netip.Addr{}, ErrDrop
	}
	out, err := netutil.Embed(prefix.Addr().As16(), 96, a.As4())
	if err != nil {
		return netip.Addr{}, ErrDrop
	}
	return netip.AddrFrom16(out), nil
}

func (m *testMapper) MapIPv6ToIPv4(a netip.Addr, allocate bool) (netip.Addr, error) {
	if r, ok := m.static6[a]; ok {
		return r, nil
	}
	if !prefix.Contains(a) {
		return netip.Addr{}, ErrReject
	}
	v4, err := netutil.Extract(a.As16(), 96)
	if err != nil {
		return netip.Addr{}, ErrDrop
	}
	r := netip.AddrFrom4(v4)
	if _, hairpin := m.static4[r]; hairpin {
		return netip.Addr{}, ErrDrop
	}
	return r, nil
}

type collector struct{ pkts [][]byte }

func (c *collector) Packet(n int) []byte {
	b := make([]byte, n)
	c.pkts = append(c.pkts, b)
	return b
}

type recorder struct {
	events     []Event
	translated int
}

func (r *recorder) Translated(uint8, int) { r.translated++ }
func (r *recorder) Event(e Event)         { r.events = append(r.events, e) }

func newTranslator(t testing.TB, mode UDPChecksumMode) (*Translator, *recorder) {
	t.Helper()
	rec := &recorder{}
	tr := New(Config{LocalAddr4: local4, LocalAddr6: local6, MTU: 1500, OfflinkMTU: 1280, UDPChecksum: mode}, newTestMapper(), rec)
	return tr, rec
}

// Packet builders.

type v4opts struct {
	tos      uint8
	ttl      uint8
	ident    uint16
	flagsOff uint16
}

func buildIPv4(src, dst netip.Addr, proto uint8, payload []byte, o v4opts) []byte {
	b := make([]byte, ipv4HdrLen+len(payload))
	b[0] = 0x45
	b[1] = o.tos
	binary.BigEndian.PutUint16(b[2:], uint16(len(b)))
	binary.BigEndian.PutUint16(b[4:], o.ident)
	binary.BigEndian.PutUint16(b[6:], o.flagsOff)
	if o.ttl == 0 {
		o.ttl = 64
	}
	b[8] = o.ttl
	b[9] = proto
	s, d := src.As4(), dst.As4()
	copy(b[12:16], s[:])
	copy(b[16:20], d[:])
	binary.BigEndian.PutUint16(b[10:], checksum(b[:ipv4HdrLen], 0))
	copy(b[ipv4HdrLen:], payload)
	return b
}

type v6opts struct {
	tc       uint8
	hop      uint8
	frag     bool
	fragOff  uint16 // bytes
	fragMF   bool
	fragID   uint32
	extHdrs  []byte // raw extension headers placed before the payload; first byte is next header
	firstExt uint8  // protocol number of the first extension header
}

func buildIPv6(src, dst netip.Addr, proto uint8, payload []byte, o v6opts) []byte {
	if o.hop == 0 {
		o.hop = 64
	}
	var ext []byte
	nextHdr := proto
	if o.frag {
		fh := make([]byte, 8)
		fh[0] = proto
		of := o.fragOff
		if o.fragMF {
			of |= 1
		}
		binary.BigEndian.PutUint16(fh[2:], of)
		binary.BigEndian.PutUint32(fh[4:], o.fragID)
		ext = fh
		nextHdr = protoFrag
	}
	if o.extHdrs != nil {
		ext = append(append([]byte{}, o.extHdrs...), ext...)
		nextHdr = o.firstExt
	}
	b := make([]byte, ipv6HdrLen+len(ext)+len(payload))
	binary.BigEndian.PutUint32(b[0:], 6<<28|uint32(o.tc)<<20)
	binary.BigEndian.PutUint16(b[4:], uint16(len(ext)+len(payload)))
	b[6] = nextHdr
	b[7] = o.hop
	s, d := src.As16(), dst.As16()
	copy(b[8:24], s[:])
	copy(b[24:40], d[:])
	copy(b[40:], ext)
	copy(b[40+len(ext):], payload)
	return b
}

func udpPayload(srcPort, dstPort uint16, data []byte, pseudo uint64, zeroCk bool) []byte {
	b := make([]byte, 8+len(data))
	binary.BigEndian.PutUint16(b[0:], srcPort)
	binary.BigEndian.PutUint16(b[2:], dstPort)
	binary.BigEndian.PutUint16(b[4:], uint16(len(b)))
	copy(b[8:], data)
	if !zeroCk {
		binary.BigEndian.PutUint16(b[6:], checksum(b, pseudo))
	}
	return b
}

func tcpPayload(srcPort, dstPort uint16, data []byte, pseudo uint64) []byte {
	b := make([]byte, 20+len(data))
	binary.BigEndian.PutUint16(b[0:], srcPort)
	binary.BigEndian.PutUint16(b[2:], dstPort)
	binary.BigEndian.PutUint32(b[4:], 1000)
	b[12] = 5 << 4
	b[13] = 0x10
	copy(b[20:], data)
	binary.BigEndian.PutUint16(b[16:], checksum(b, pseudo))
	return b
}

func icmpPayload(typ, code uint8, word uint32, data []byte, pseudo uint64) []byte {
	b := make([]byte, 8+len(data))
	b[0], b[1] = typ, code
	binary.BigEndian.PutUint32(b[4:], word)
	copy(b[8:], data)
	binary.BigEndian.PutUint16(b[2:], checksum(b, pseudo))
	return b
}

func pseudo4Of(src, dst netip.Addr, length int, proto uint8) uint64 {
	s, d := src.As4(), dst.As4()
	return pseudo4(s[:], d[:], length, proto)
}

func pseudo6Of(src, dst netip.Addr, length int, proto uint8) uint64 {
	s, d := src.As16(), dst.As16()
	return pseudo6(s[:], d[:], length, proto)
}

// checkOutput validates the IP header and the transport checksum of an
// output packet and returns the transport payload.
func checkOutput(t *testing.T, b []byte) (family uint8, proto uint8, payload []byte) {
	t.Helper()
	switch b[0] >> 4 {
	case 4:
		ihl := int(b[0]&0xf) * 4
		if !verify(b[:ihl], 0) {
			t.Fatalf("bad IPv4 header checksum")
		}
		if ip4TotalLen(b) != len(b) {
			t.Fatalf("IPv4 total length %d != %d", ip4TotalLen(b), len(b))
		}
		proto = b[9]
		payload = b[ihl:]
		if ip4FlagsOff(b)&ip4OffMask != 0 {
			return 4, proto, payload
		}
		var ps uint64
		switch proto {
		case protoTCP, protoUDP:
			ps = pseudo4(b[12:16], b[16:20], len(payload), proto)
		}
		if proto == protoUDP && binary.BigEndian.Uint16(payload[6:]) == 0 {
			return 4, proto, payload
		}
		if !verify(payload, ps) {
			t.Fatalf("bad IPv4 transport checksum (proto %d)", proto)
		}
		return 4, proto, payload
	case 6:
		if ip6PayloadLen(b) != len(b)-ipv6HdrLen {
			t.Fatalf("IPv6 payload length %d != %d", ip6PayloadLen(b), len(b)-ipv6HdrLen)
		}
		proto = b[6]
		payload = b[ipv6HdrLen:]
		if proto == protoFrag {
			fh := payload[:8]
			proto = fh[0]
			payload = payload[8:]
			if fragOffFlags(fh)&ip6FragMask != 0 {
				return 6, proto, payload
			}
		}
		if proto == protoUDP && binary.BigEndian.Uint16(payload[6:]) == 0 {
			return 6, proto, payload
		}
		if !verify(payload, pseudo6(b[8:24], b[24:40], len(payload), proto)) {
			t.Fatalf("bad IPv6 transport checksum (proto %d)", proto)
		}
		return 6, proto, payload
	}
	t.Fatalf("bad IP version")
	return 0, 0, nil
}

func srcDst4(b []byte) (netip.Addr, netip.Addr) {
	return netip.AddrFrom4([4]byte(b[12:16])), netip.AddrFrom4([4]byte(b[16:20]))
}

func srcDst6(b []byte) (netip.Addr, netip.Addr) {
	return netip.AddrFrom16([16]byte(b[8:24])), netip.AddrFrom16([16]byte(b[24:40]))
}

func one(t *testing.T, c *collector) []byte {
	t.Helper()
	if len(c.pkts) != 1 {
		t.Fatalf("expected 1 output packet, got %d", len(c.pkts))
	}
	return c.pkts[0]
}

// Tests.

func TestUDP4to6(t *testing.T) {
	tr, rec := newTranslator(t, UDPChecksumDrop)
	data := []byte("hello world")
	udp := udpPayload(1234, 53, data, pseudo4Of(remote4, host4, 8+len(data), protoUDP), false)
	in := buildIPv4(remote4, host4, protoUDP, udp, v4opts{tos: 0x28, ttl: 10, flagsOff: ip4FlagDF})
	c := &collector{}
	tr.Translate(in, c)
	out := one(t, c)
	fam, proto, payload := checkOutput(t, out)
	if fam != 6 || proto != protoUDP {
		t.Fatalf("family %d proto %d", fam, proto)
	}
	s, d := srcDst6(out)
	if s != remote6 || d != host6 {
		t.Fatalf("addresses %s -> %s", s, d)
	}
	if uint8(ip6VerTcFl(out)>>20) != 0x28 {
		t.Errorf("traffic class not preserved")
	}
	if out[7] != 9 {
		t.Errorf("hop limit %d, want 9", out[7])
	}
	if !bytes.Equal(payload[8:], data) {
		t.Errorf("payload mismatch")
	}
	if rec.translated != 1 || len(rec.events) != 0 {
		t.Errorf("translated=%d events=%v", rec.translated, rec.events)
	}
}

func TestTCP6to4(t *testing.T) {
	tr, _ := newTranslator(t, UDPChecksumDrop)
	data := bytes.Repeat([]byte{0xab}, 100)
	tcp := tcpPayload(4000, 80, data, pseudo6Of(host6, remote6, 20+len(data), protoTCP))
	in := buildIPv6(host6, remote6, protoTCP, tcp, v6opts{tc: 0x10, hop: 5})
	c := &collector{}
	tr.Translate(in, c)
	out := one(t, c)
	fam, proto, payload := checkOutput(t, out)
	if fam != 4 || proto != protoTCP {
		t.Fatalf("family %d proto %d", fam, proto)
	}
	s, d := srcDst4(out)
	if s != host4 || d != remote4 {
		t.Fatalf("addresses %s -> %s", s, d)
	}
	if out[1] != 0x10 || out[8] != 4 {
		t.Errorf("tos %#x ttl %d", out[1], out[8])
	}
	if ip4FlagsOff(out)&ip4FlagDF != 0 {
		t.Errorf("DF set on small packet")
	}
	if !bytes.Equal(payload[20:], data) {
		t.Errorf("payload mismatch")
	}
}

func TestRoundTrip4to6to4(t *testing.T) {
	tr, _ := newTranslator(t, UDPChecksumDrop)
	data := []byte("round trip")
	tcp := tcpPayload(1, 2, data, pseudo4Of(remote4, host4, 20+len(data), protoTCP))
	in := buildIPv4(remote4, host4, protoTCP, tcp, v4opts{ttl: 64, flagsOff: ip4FlagDF})
	orig := append([]byte{}, in...)
	c1 := &collector{}
	tr.Translate(in, c1)
	c2 := &collector{}
	tr.Translate(one(t, c1), c2)
	out := one(t, c2)
	checkOutput(t, out)
	// TTL dropped by two, ident/flags/checksum differ; compare the rest.
	if !bytes.Equal(out[20:], orig[20:]) {
		t.Errorf("transport payload changed over round trip")
	}
	if out[8] != 62 {
		t.Errorf("ttl %d", out[8])
	}
	s, d := srcDst4(out)
	if s != remote4 || d != host4 {
		t.Fatalf("addresses %s -> %s", s, d)
	}
}

func TestEcho4to6AndBack(t *testing.T) {
	tr, _ := newTranslator(t, UDPChecksumDrop)
	data := []byte("ping")
	icmp := icmpPayload(8, 0, 0x12340001, data, 0)
	in := buildIPv4(remote4, host4, protoICMP, icmp, v4opts{})
	c := &collector{}
	tr.Translate(in, c)
	out := one(t, c)
	fam, proto, payload := checkOutput(t, out)
	if fam != 6 || proto != protoICMPv6 || payload[0] != 128 {
		t.Fatalf("family %d proto %d type %d", fam, proto, payload[0])
	}
	// Reply from host6.
	reply := icmpPayload(129, 0, 0x12340001, data, pseudo6Of(host6, remote6, 8+len(data), protoICMPv6))
	in6 := buildIPv6(host6, remote6, protoICMPv6, reply, v6opts{})
	c = &collector{}
	tr.Translate(in6, c)
	out = one(t, c)
	fam, proto, payload = checkOutput(t, out)
	if fam != 4 || proto != protoICMP || payload[0] != 0 {
		t.Fatalf("family %d proto %d type %d", fam, proto, payload[0])
	}
	if !bytes.Equal(payload[8:], data) {
		t.Errorf("echo data mismatch")
	}
}

func TestPingSelf(t *testing.T) {
	tr, rec := newTranslator(t, UDPChecksumDrop)
	icmp := icmpPayload(8, 0, 7, []byte("x"), 0)
	in := buildIPv4(remote4, local4, protoICMP, icmp, v4opts{tos: 4})
	c := &collector{}
	tr.Translate(in, c)
	out := one(t, c)
	_, proto, payload := checkOutput(t, out)
	s, d := srcDst4(out)
	if proto != protoICMP || payload[0] != 0 || s != local4 || d != remote4 || out[1] != 4 {
		t.Fatalf("bad echo reply")
	}

	icmp6 := icmpPayload(128, 0, 7, []byte("y"), pseudo6Of(host6, local6, 9, protoICMPv6))
	in6 := buildIPv6(host6, local6, protoICMPv6, icmp6, v6opts{tc: 3})
	c = &collector{}
	tr.Translate(in6, c)
	out = one(t, c)
	_, proto, payload = checkOutput(t, out)
	s6, d6 := srcDst6(out)
	if proto != protoICMPv6 || payload[0] != 129 || s6 != local6 || d6 != host6 || uint8(ip6VerTcFl(out)>>20) != 3 {
		t.Fatalf("bad echo6 reply")
	}
	if len(rec.events) != 2 || rec.events[0].Kind != KindSelf || rec.events[1].Kind != KindSelf {
		t.Errorf("events %v", rec.events)
	}
}

func TestTTLExpired(t *testing.T) {
	tr, rec := newTranslator(t, UDPChecksumDrop)
	udp := udpPayload(1, 2, []byte("a"), pseudo4Of(remote4, host4, 9, protoUDP), false)
	in := buildIPv4(remote4, host4, protoUDP, udp, v4opts{ttl: 1})
	c := &collector{}
	tr.Translate(in, c)
	out := one(t, c)
	_, proto, payload := checkOutput(t, out)
	s, d := srcDst4(out)
	if proto != protoICMP || payload[0] != 11 || payload[1] != 0 || s != local4 || d != remote4 {
		t.Fatalf("expected time exceeded from %s", local4)
	}
	if !bytes.Equal(payload[8:], in) {
		t.Errorf("embedded packet mismatch")
	}
	if len(rec.events) != 1 || rec.events[0].Reason != ReasonTimeExceeded {
		t.Errorf("events %v", rec.events)
	}

	in6 := buildIPv6(host6, remote6, protoUDP, udpPayload(1, 2, []byte("a"), pseudo6Of(host6, remote6, 9, protoUDP), false), v6opts{hop: 1})
	c = &collector{}
	tr.Translate(in6, c)
	out = one(t, c)
	_, proto, payload = checkOutput(t, out)
	if proto != protoICMPv6 || payload[0] != 3 {
		t.Fatalf("expected ICMPv6 time exceeded")
	}
}

func TestDFTooBig(t *testing.T) {
	tr, _ := newTranslator(t, UDPChecksumDrop)
	data := make([]byte, 1490)
	udp := udpPayload(1, 2, data, pseudo4Of(remote4, host4, 8+len(data), protoUDP), false)
	in := buildIPv4(remote4, host4, protoUDP, udp, v4opts{flagsOff: ip4FlagDF})
	c := &collector{}
	tr.Translate(in, c)
	out := one(t, c)
	_, proto, payload := checkOutput(t, out)
	if proto != protoICMP || payload[0] != 3 || payload[1] != 4 {
		t.Fatalf("expected frag needed, got type %d code %d", payload[0], payload[1])
	}
	if mtu := icmpWord(payload) & 0xffff; mtu != 1480 {
		t.Errorf("mtu %d, want 1480", mtu)
	}
	if len(out) != 576 {
		t.Errorf("ICMP error length %d, want 576", len(out))
	}
}

func TestFragment4to6(t *testing.T) {
	tr, _ := newTranslator(t, UDPChecksumDrop)
	data := make([]byte, 3000)
	for i := range data {
		data[i] = byte(i)
	}
	udp := udpPayload(1, 2, data, pseudo4Of(remote4, host4, 8+len(data), protoUDP), false)
	in := buildIPv4(remote4, host4, protoUDP, udp, v4opts{ident: 0xbeef})
	c := &collector{}
	tr.Translate(in, c)
	if len(c.pkts) < 3 {
		t.Fatalf("expected at least 3 fragments, got %d", len(c.pkts))
	}
	var reassembled []byte
	for i, f := range c.pkts {
		if len(f) > 1280 {
			t.Errorf("fragment %d is %d bytes", i, len(f))
		}
		if f[6] != protoFrag {
			t.Fatalf("fragment %d has no fragment header", i)
		}
		fh := f[40:48]
		if fh[0] != protoUDP || fragIdent(fh) != 0xbeef {
			t.Errorf("fragment header nh=%d id=%#x", fh[0], fragIdent(fh))
		}
		of := fragOffFlags(fh)
		if int(of&ip6FragMask) != len(reassembled) {
			t.Errorf("fragment %d offset %d, want %d", i, of&ip6FragMask, len(reassembled))
		}
		last := i == len(c.pkts)-1
		if (of&ip6FragMF != 0) == last {
			t.Errorf("fragment %d MF flag wrong", i)
		}
		reassembled = append(reassembled, f[48:]...)
	}
	// The first fragment carries the UDP header with a checksum valid for the
	// whole datagram.
	if !verify(reassembled, pseudo6Of(remote6, host6, len(reassembled), protoUDP)) {
		t.Errorf("reassembled UDP checksum invalid")
	}
	if !bytes.Equal(reassembled[8:], data) {
		t.Errorf("reassembled payload mismatch")
	}
}

func TestFragment6to4(t *testing.T) {
	tr, _ := newTranslator(t, UDPChecksumDrop)
	// Second fragment of a UDP datagram: no transport header.
	chunk := bytes.Repeat([]byte{7}, 64)
	in := buildIPv6(host6, remote6, protoUDP, chunk, v6opts{frag: true, fragOff: 1232, fragMF: true, fragID: 0x00015678})
	c := &collector{}
	tr.Translate(in, c)
	out := one(t, c)
	if out[9] != protoUDP {
		t.Fatalf("proto %d", out[9])
	}
	if ip4Ident(out) != 0x5678 {
		t.Errorf("ident %#x", ip4Ident(out))
	}
	fo := ip4FlagsOff(out)
	if fo&ip4FlagMF == 0 || int(fo&ip4OffMask)*8 != 1232 || fo&ip4FlagDF != 0 {
		t.Errorf("flags/offset %#x", fo)
	}
	if !bytes.Equal(out[20:], chunk) {
		t.Errorf("payload mismatch")
	}
}

func TestPacketTooBig6to4(t *testing.T) {
	tr, _ := newTranslator(t, UDPChecksumDrop)
	data := make([]byte, 1480)
	udp := udpPayload(1, 2, data, pseudo6Of(host6, remote6, 8+len(data), protoUDP), false)
	in := buildIPv6(host6, remote6, protoUDP, udp, v6opts{})
	c := &collector{}
	tr.Translate(in, c)
	out := one(t, c)
	_, proto, payload := checkOutput(t, out)
	if proto != protoICMPv6 || payload[0] != 2 || icmpWord(payload) != 1500 {
		t.Fatalf("expected PTB 1500, got type %d word %d", payload[0], icmpWord(payload))
	}
	if len(out) > 1280 {
		t.Errorf("PTB message is %d bytes", len(out))
	}
	// A large packet that fits the MTU gets DF set on the IPv4 side.
	data = make([]byte, 1400)
	udp = udpPayload(1, 2, data, pseudo6Of(host6, remote6, 8+len(data), protoUDP), false)
	in = buildIPv6(host6, remote6, protoUDP, udp, v6opts{})
	c = &collector{}
	tr.Translate(in, c)
	out = one(t, c)
	checkOutput(t, out)
	if ip4FlagsOff(out) != ip4FlagDF {
		t.Errorf("flags %#x, want DF", ip4FlagsOff(out))
	}
}

func TestICMPError4to6PortUnreachable(t *testing.T) {
	tr, _ := newTranslator(t, UDPChecksumDrop)
	// host6 sent UDP to remote6; remote4 replies with port unreachable
	// embedding the translated IPv4 packet.
	data := []byte("query")
	udpEm := udpPayload(5000, 53, data, pseudo4Of(host4, remote4, 8+len(data), protoUDP), false)
	em := buildIPv4(host4, remote4, protoUDP, udpEm, v4opts{ttl: 63})
	icmp := icmpPayload(3, 3, 0, em, 0)
	in := buildIPv4(remote4, host4, protoICMP, icmp, v4opts{ttl: 50})
	c := &collector{}
	tr.Translate(in, c)
	out := one(t, c)
	_, proto, payload := checkOutput(t, out)
	s, d := srcDst6(out)
	if proto != protoICMPv6 || s != remote6 || d != host6 {
		t.Fatalf("proto %d %s -> %s", proto, s, d)
	}
	if payload[0] != 1 || payload[1] != 4 {
		t.Fatalf("type %d code %d, want 1/4", payload[0], payload[1])
	}
	inner := payload[8:]
	is, id := srcDst6(inner)
	if is != host6 || id != remote6 || inner[6] != protoUDP || inner[7] != 63 {
		t.Fatalf("inner header wrong: %s -> %s nh %d hop %d", is, id, inner[6], inner[7])
	}
	if ip6PayloadLen(inner) != len(udpEm) {
		t.Errorf("inner payload length %d", ip6PayloadLen(inner))
	}
	innerUDP := inner[40:]
	if !verify(innerUDP, pseudo6Of(host6, remote6, len(innerUDP), protoUDP)) {
		t.Errorf("inner UDP checksum not adjusted")
	}
}

func TestICMPError6to4PacketTooBig(t *testing.T) {
	tr, _ := newTranslator(t, UDPChecksumDrop)
	data := bytes.Repeat([]byte{1}, 200)
	tcpEm := tcpPayload(80, 4000, data, pseudo6Of(remote6, host6, 20+len(data), protoTCP))
	em := buildIPv6(remote6, host6, protoTCP, tcpEm, v6opts{hop: 60})
	icmp := icmpPayload(2, 0, 1400, em, pseudo6Of(host6, remote6, 8+len(em), protoICMPv6))
	in := buildIPv6(host6, remote6, protoICMPv6, icmp, v6opts{})
	c := &collector{}
	tr.Translate(in, c)
	out := one(t, c)
	_, proto, payload := checkOutput(t, out)
	if proto != protoICMP || payload[0] != 3 || payload[1] != 4 {
		t.Fatalf("type %d code %d", payload[0], payload[1])
	}
	if mtu := icmpWord(payload) & 0xffff; mtu != 1380 {
		t.Errorf("mtu %d, want 1380", mtu)
	}
	inner := payload[8:]
	if !verify(inner[:20], 0) {
		t.Errorf("inner IPv4 checksum invalid")
	}
	is, id := srcDst4(inner)
	if is != remote4 || id != host4 || inner[9] != protoTCP || inner[8] != 60 {
		t.Fatalf("inner %s -> %s proto %d ttl %d", is, id, inner[9], inner[8])
	}
	if len(out) > 576 {
		t.Errorf("ICMPv4 error is %d bytes", len(out))
	}
	innerTCP := inner[20:]
	// The embedded packet was truncated; checksum must be computed over the
	// original length, which we cannot verify here, so check the adjust
	// arithmetic by recomputing what the full packet would carry.
	full := tcpPayload(80, 4000, data, pseudo4Of(remote4, host4, 20+len(data), protoTCP))
	if binary.BigEndian.Uint16(innerTCP[16:]) != binary.BigEndian.Uint16(full[16:]) {
		t.Errorf("inner TCP checksum %#x, want %#x", innerTCP[16:18], full[16:18])
	}
}

func TestUnmappable(t *testing.T) {
	tr, rec := newTranslator(t, UDPChecksumDrop)
	udp := udpPayload(1, 2, []byte("a"), pseudo6Of(unmap6, remote6, 9, protoUDP), false)
	in := buildIPv6(unmap6, remote6, protoUDP, udp, v6opts{})
	c := &collector{}
	tr.Translate(in, c)
	out := one(t, c)
	_, proto, payload := checkOutput(t, out)
	s, d := srcDst6(out)
	if proto != protoICMPv6 || payload[0] != 1 || payload[1] != 5 || s != local6 || d != unmap6 {
		t.Fatalf("expected unreachable code 5 from %s", local6)
	}
	if rec.events[0].Kind != KindReject || rec.events[0].Reason != ReasonSourceUnmappable {
		t.Errorf("event %v", rec.events[0])
	}

	// Destination outside the prefix.
	udp = udpPayload(1, 2, []byte("a"), pseudo6Of(host6, unmap6, 9, protoUDP), false)
	in = buildIPv6(host6, unmap6, protoUDP, udp, v6opts{})
	c = &collector{}
	tr.Translate(in, c)
	out = one(t, c)
	_, proto, payload = checkOutput(t, out)
	if proto != protoICMPv6 || payload[0] != 1 || payload[1] != 0 {
		t.Fatalf("expected unreachable code 0")
	}

	// IPv4 source that the mapper rejects.
	tr.mapper.(*testMapper).reject4[remote4] = true
	in4 := buildIPv4(remote4, host4, protoUDP, udpPayload(1, 2, []byte("a"), pseudo4Of(remote4, host4, 9, protoUDP), false), v4opts{})
	c = &collector{}
	tr.Translate(in4, c)
	out = one(t, c)
	_, proto, payload = checkOutput(t, out)
	if proto != protoICMP || payload[0] != 3 || payload[1] != 10 {
		t.Fatalf("expected ICMPv4 unreachable code 10, got %d/%d", payload[0], payload[1])
	}
}

func TestUDPZeroChecksum(t *testing.T) {
	udp := udpPayload(1, 2, []byte("zero"), 0, true)
	for _, tc := range []struct {
		mode UDPChecksumMode
		want int
	}{{UDPChecksumDrop, 0}, {UDPChecksumForward, 1}, {UDPChecksumCalc, 1}} {
		tr, rec := newTranslator(t, tc.mode)
		in := buildIPv4(remote4, host4, protoUDP, append([]byte{}, udp...), v4opts{})
		c := &collector{}
		tr.Translate(in, c)
		if len(c.pkts) != tc.want {
			t.Fatalf("mode %s: %d packets", tc.mode, len(c.pkts))
		}
		switch tc.mode {
		case UDPChecksumDrop:
			if rec.events[0].Reason != ReasonUDPZeroChecksum {
				t.Errorf("reason %s", rec.events[0].Reason)
			}
		case UDPChecksumForward:
			if binary.BigEndian.Uint16(c.pkts[0][46:]) != 0 {
				t.Errorf("checksum was filled in")
			}
		case UDPChecksumCalc:
			checkOutput(t, c.pkts[0])
			if binary.BigEndian.Uint16(c.pkts[0][46:]) == 0 {
				t.Errorf("checksum not computed")
			}
		}
	}
}

func TestInvalidPackets(t *testing.T) {
	tr, rec := newTranslator(t, UDPChecksumDrop)
	cases := map[string][]byte{
		"short":       {0x45, 0, 0, 10},
		"bad version": {0x35, 0, 0, 20, 0, 0, 0, 0, 64, 17, 0, 0, 1, 2, 3, 4, 5, 6, 7, 8},
		"bad checksum": func() []byte {
			b := buildIPv4(remote4, host4, protoUDP, make([]byte, 8), v4opts{})
			b[10] ^= 0xff
			return b
		}(),
		"ttl zero":     buildIPv4(remote4, host4, protoUDP, make([]byte, 8), v4opts{ttl: 0xff}),
		"icmp cksum":   buildIPv4(remote4, host4, protoICMP, make([]byte, 8), v4opts{}),
		"v6 short":     {0x60, 0, 0, 0},
		"v6 multicast": buildIPv6(host6, netip.MustParseAddr("ff02::1"), protoUDP, make([]byte, 8), v6opts{}),
		"v4 in v6":     buildIPv6(host6, remote6, protoICMP, make([]byte, 8), v6opts{}),
		"v6 in v4":     buildIPv4(remote4, host4, protoICMPv6, make([]byte, 8), v4opts{}),
		"bad frag":     buildIPv6(host6, remote6, protoUDP, make([]byte, 4), v6opts{}),
	}
	delete(cases, "ttl zero") // builder substitutes 64 for 0; covered by "bad frag" style below
	for name, b := range cases {
		c := &collector{}
		tr.Translate(b, c)
		if len(c.pkts) != 0 {
			t.Errorf("%s: produced %d packets", name, len(c.pkts))
		}
	}
	if rec.translated != 0 {
		t.Errorf("translated %d", rec.translated)
	}
	// A TTL of zero is dropped.
	b := buildIPv4(remote4, host4, protoUDP, make([]byte, 8), v4opts{})
	b[8] = 0
	binary.BigEndian.PutUint16(b[10:], 0)
	binary.BigEndian.PutUint16(b[10:], checksum(b[:20], 0))
	c := &collector{}
	tr.Translate(b, c)
	if len(c.pkts) != 0 {
		t.Errorf("ttl zero produced output")
	}
}

func TestRoutingHeaderSegmentsLeft(t *testing.T) {
	tr, rec := newTranslator(t, UDPChecksumDrop)
	// Type 0 routing header, 1 segment left, one address.
	rh := make([]byte, 24)
	rh[0] = protoUDP
	rh[1] = 2 // (2+1)*8 = 24 bytes
	rh[2] = 0
	rh[3] = 1
	udp := udpPayload(1, 2, []byte("a"), 0, true)
	in := buildIPv6(host6, remote6, protoUDP, udp, v6opts{extHdrs: rh, firstExt: 43})
	c := &collector{}
	tr.Translate(in, c)
	out := one(t, c)
	_, proto, payload := checkOutput(t, out)
	if proto != protoICMPv6 || payload[0] != 4 || payload[1] != 0 || icmpWord(payload) != 44 {
		t.Fatalf("expected param problem pointer 44, got type %d word %d", payload[0], icmpWord(payload))
	}
	if rec.events[0].Reason != ReasonRoutingHeaderSegmentsLeft {
		t.Errorf("event %v", rec.events[0])
	}
}

func TestHopByHopIsSkipped(t *testing.T) {
	tr, _ := newTranslator(t, UDPChecksumDrop)
	hbh := make([]byte, 8)
	hbh[0] = protoUDP
	hbh[1] = 0
	hbh[2], hbh[3] = 1, 4 // PadN option
	data := []byte("opts")
	udp := udpPayload(1, 2, data, pseudo6Of(host6, remote6, 8+len(data), protoUDP), false)
	in := buildIPv6(host6, remote6, protoUDP, udp, v6opts{extHdrs: hbh, firstExt: 0})
	c := &collector{}
	tr.Translate(in, c)
	out := one(t, c)
	_, proto, payload := checkOutput(t, out)
	if proto != protoUDP || !bytes.Equal(payload[8:], data) {
		t.Fatalf("hop-by-hop packet not translated")
	}
}

func FuzzTranslate(f *testing.F) {
	tr, _ := newTranslator(f, UDPChecksumCalc)
	f.Add(buildIPv4(remote4, host4, protoUDP, udpPayload(1, 2, []byte("a"), 0, true), v4opts{}))
	f.Add(buildIPv6(host6, remote6, protoTCP, tcpPayload(1, 2, []byte("a"), 0), v6opts{}))
	f.Add(buildIPv4(remote4, host4, protoICMP, icmpPayload(3, 3, 0, buildIPv4(host4, remote4, protoUDP, make([]byte, 8), v4opts{}), 0), v4opts{}))
	f.Add(buildIPv6(host6, remote6, protoICMPv6, icmpPayload(2, 0, 1300, buildIPv6(remote6, host6, protoUDP, make([]byte, 8), v6opts{}), 0), v6opts{}))
	f.Add(buildIPv6(host6, remote6, protoUDP, make([]byte, 64), v6opts{frag: true, fragOff: 8, fragMF: true}))
	f.Fuzz(func(t *testing.T, b []byte) {
		c := &collector{}
		tr.Translate(b, c)
		for _, p := range c.pkts {
			if len(p) < 20 || len(p) > 65535 {
				t.Fatalf("output packet of %d bytes", len(p))
			}
		}
	})
}
