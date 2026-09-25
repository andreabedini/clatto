// Package xlate implements stateless IP/ICMP translation between IPv4 and
// IPv6 (RFC 7915) in the manner of tayga. It has no I/O: packets come in as
// byte slices and go out through an Emitter.
package xlate

import (
	"errors"
	"math/rand/v2"
	"net/netip"
)

const (
	ipv4HdrLen = 20
	ipv6HdrLen = 40
	fragHdrLen = 8
	icmpHdrLen = 8

	// mtuAdj is the difference between the IPv6 and IPv4 header sizes.
	mtuAdj = 20
	// mtuMin is the minimum IPv6 link MTU.
	mtuMin = 1280
	// icmp4MaxLen is the maximum size of a generated ICMPv4 error message.
	icmp4MaxLen = 576

	ip4FlagDF   = 0x4000
	ip4FlagMF   = 0x2000
	ip4OffMask  = 0x1fff
	ip6FragMF   = 0x0001
	ip6FragMask = 0xfff8

	protoICMP   = 1
	protoTCP    = 6
	protoUDP    = 17
	protoFrag   = 44
	protoICMPv6 = 58
)

// Errors returned by a Mapper.
var (
	// ErrReject means the address cannot be mapped and the sender should be
	// told with an ICMP error.
	ErrReject = errors.New("address rejected")
	// ErrDrop means the packet should be discarded silently.
	ErrDrop = errors.New("address dropped")
)

// Mapper translates addresses between the two families.
type Mapper interface {
	// MapIPv4ToIPv6 returns the IPv6 address corresponding to addr4.
	MapIPv4ToIPv6(addr4 netip.Addr) (netip.Addr, error)
	// MapIPv6ToIPv4 returns the IPv4 address corresponding to addr6. When
	// allocate is true the mapper may create a new dynamic mapping.
	MapIPv6ToIPv4(addr6 netip.Addr, allocate bool) (netip.Addr, error)
}

// Emitter receives translated packets.
type Emitter interface {
	// Packet returns a buffer of exactly n bytes that the translator fills
	// with an outbound IP packet. Returning nil drops the packet.
	Packet(n int) []byte
}

// UDPChecksumMode says what to do with IPv4 UDP datagrams that carry no
// checksum, and with IPv6 datagrams whose checksum is zero.
type UDPChecksumMode uint8

const (
	// UDPChecksumDrop discards such datagrams (RFC 7915 default).
	UDPChecksumDrop UDPChecksumMode = iota
	// UDPChecksumCalc computes a real checksum before forwarding.
	UDPChecksumCalc
	// UDPChecksumForward forwards them unchanged.
	UDPChecksumForward
)

func (m UDPChecksumMode) String() string {
	switch m {
	case UDPChecksumDrop:
		return "drop"
	case UDPChecksumCalc:
		return "calc"
	case UDPChecksumForward:
		return "forward"
	}
	return "unknown"
}

// Config holds the translator's immutable parameters.
type Config struct {
	// LocalAddr4 and LocalAddr6 are the translator's own addresses. ICMP
	// errors are sourced from them and echo requests to them are answered.
	LocalAddr4 netip.Addr
	LocalAddr6 netip.Addr
	// MTU is the MTU of the tun interface.
	MTU int
	// OfflinkMTU bounds the size of IPv6 packets produced from IPv4 packets
	// without DF; larger ones are fragmented. Never below 1280.
	OfflinkMTU int
	// UDPChecksum selects the treatment of zero UDP checksums.
	UDPChecksum UDPChecksumMode
}

// Translator converts packets. It is safe for concurrent use.
type Translator struct {
	cfg    Config
	mapper Mapper
	obs    Observer
	local4 [4]byte
	local6 [16]byte
}

// New builds a Translator. obs may be nil.
func New(cfg Config, m Mapper, obs Observer) *Translator {
	if obs == nil {
		obs = NopObserver{}
	}
	if cfg.OfflinkMTU < mtuMin {
		cfg.OfflinkMTU = mtuMin
	}
	return &Translator{
		cfg:    cfg,
		mapper: m,
		obs:    obs,
		local4: cfg.LocalAddr4.As4(),
		local6: cfg.LocalAddr6.As16(),
	}
}

// Config returns the translator's configuration.
func (t *Translator) Config() Config { return t.cfg }

// Translate handles one inbound packet. It may modify pkt in place. Zero or
// more outbound packets are produced through out.
func (t *Translator) Translate(pkt []byte, out Emitter) {
	if len(pkt) == 0 {
		return
	}
	switch pkt[0] >> 4 {
	case 4:
		t.handleIPv4(pkt, out)
	case 6:
		t.handleIPv6(pkt, out)
	default:
		t.obs.Event(Event{Kind: KindDrop, Reason: ReasonUnknownIPVersion, Length: len(pkt)})
	}
}

func (t *Translator) map4to6(a []byte) ([16]byte, error) {
	r, err := t.mapper.MapIPv4ToIPv6(netip.AddrFrom4([4]byte(a[:4])))
	if err != nil {
		return [16]byte{}, err
	}
	if !r.Is6() {
		return [16]byte{}, ErrDrop
	}
	return r.As16(), nil
}

func (t *Translator) map6to4(a []byte, allocate bool) ([4]byte, error) {
	r, err := t.mapper.MapIPv6ToIPv4(netip.AddrFrom16([16]byte(a[:16])), allocate)
	if err != nil {
		return [4]byte{}, err
	}
	if !r.Is4() {
		return [4]byte{}, ErrDrop
	}
	return r.As4(), nil
}

// randomIdent produces an IPv4 identification value for packets that had no
// fragment header on the IPv6 side (RFC 7739 recommends unpredictability).
func randomIdent() uint16 {
	return uint16(rand.Uint32())
}
