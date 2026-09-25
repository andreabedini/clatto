package xlate

import (
	"encoding/binary"
	"net/netip"

	"github.com/andreabedini/clatto/internal/netutil"
)

// pkt is a parsed view over a packet. Slices alias the original buffer.
//
// Following tayga, hdrLen has a different meaning per family: for IPv4 it is
// the IP header length; for IPv6 it is the length of the extension headers
// (including a fragment header) after the fixed 40-byte header.
type pkt struct {
	raw    []byte // the whole packet
	ip     []byte // IPv4 header (IHL bytes) or the fixed IPv6 header (40 bytes)
	hdrLen int
	data   []byte // transport payload
	proto  uint8
	frag   []byte // IPv6 fragment header, or nil
	icmp   []byte // ICMP header (8 bytes), or nil
}

func (p *pkt) family() uint8 { return p.raw[0] >> 4 }

func (p *pkt) event(kind Kind, reason Reason) Event {
	e := Event{Kind: kind, Reason: reason, Family: p.family(), Proto: p.proto}
	if p.ip == nil {
		e.Length = len(p.raw)
		return e
	}
	switch e.Family {
	case 4:
		e.Src = netip.AddrFrom4([4]byte(p.ip[12:16]))
		e.Dst = netip.AddrFrom4([4]byte(p.ip[16:20]))
		e.Length = p.hdrLen + len(p.data)
	case 6:
		e.Src = netip.AddrFrom16([16]byte(p.ip[8:24]))
		e.Dst = netip.AddrFrom16([16]byte(p.ip[24:40]))
		e.Length = ipv6HdrLen + p.hdrLen + len(p.data)
	}
	return e
}

// IPv4 header accessors.
func ip4TotalLen(h []byte) int     { return int(binary.BigEndian.Uint16(h[2:])) }
func ip4Ident(h []byte) uint16     { return binary.BigEndian.Uint16(h[4:]) }
func ip4FlagsOff(h []byte) uint16  { return binary.BigEndian.Uint16(h[6:]) }
func ip6VerTcFl(h []byte) uint32   { return binary.BigEndian.Uint32(h[0:]) }
func ip6PayloadLen(h []byte) int   { return int(binary.BigEndian.Uint16(h[4:])) }
func icmpWord(h []byte) uint32     { return binary.BigEndian.Uint32(h[4:]) }
func fragOffFlags(h []byte) uint16 { return binary.BigEndian.Uint16(h[2:]) }
func fragIdent(h []byte) uint32    { return binary.BigEndian.Uint32(h[4:]) }

// parseIPv4 mirrors tayga's parse_ip4. On failure it returns the reason and
// the caller decides whether to report it.
func parseIPv4(p *pkt) Reason {
	raw := p.raw
	if len(raw) < ipv4HdrLen {
		return ReasonIPHeaderLength
	}
	ihl := int(raw[0]&0x0f) * 4
	total := ip4TotalLen(raw)
	if raw[0]>>4 != 4 || ihl < ipv4HdrLen || len(raw) < ihl || total < ihl ||
		netutil.ClassifyIPv4([4]byte(raw[12:16])) == netutil.IPv4Invalid ||
		netutil.ClassifyIPv4([4]byte(raw[16:20])) == netutil.IPv4Invalid {
		p.ip = raw[:ipv4HdrLen]
		p.hdrLen = ipv4HdrLen
		return ReasonIPHeaderInvalid
	}
	p.ip = raw[:ihl]
	p.hdrLen = ihl
	end := len(raw)
	if end > total {
		end = total
	}
	p.data = raw[ihl:end]
	p.proto = raw[9]

	switch p.proto {
	case protoICMP:
		if ip4FlagsOff(raw)&(ip4OffMask|ip4FlagMF) != 0 {
			return ReasonICMPFragmented
		}
		if len(p.data) < icmpHdrLen {
			return ReasonICMPHeaderLength
		}
		p.icmp = p.data[:icmpHdrLen]
	case 0, 43, 44, 58, 60: // IPv6 extension headers and ICMPv6
		return ReasonIPv6OnlyProto
	default:
		fo := ip4FlagsOff(raw)
		if fo&ip4FlagMF != 0 && len(p.data)&7 != 0 {
			return ReasonFragmentMisaligned
		}
		if int(fo&ip4OffMask)*8+len(p.data) > 65535 {
			return ReasonFragmentTooLong
		}
	}
	return ReasonNone
}

// parseIPv6 mirrors tayga's parse_ip6. It returns the failure reason and,
// for a routing header with segments left, the pointer for the Parameter
// Problem message. silent is set when the failure must not be reported
// (multicast source or destination).
func parseIPv6(p *pkt) (reason Reason, segPtr int, silent bool) {
	raw := p.raw
	if len(raw) < ipv6HdrLen {
		return ReasonIPHeaderLength, 0, false
	}
	p.ip = raw[:ipv6HdrLen]
	if raw[0]>>4 != 6 || !netutil.ValidIPv6([16]byte(raw[8:24])) || !netutil.ValidIPv6([16]byte(raw[24:40])) {
		if raw[8] == 0xff || raw[24] == 0xff {
			return ReasonIPHeaderInvalid, 0, true
		}
		return ReasonIPHeaderInvalid, 0, false
	}
	p.proto = raw[6]
	data := raw[ipv6HdrLen:]
	if pl := ip6PayloadLen(raw); len(data) > pl {
		data = data[:pl]
	}

	segLeft := 0
	segPtr = ipv6HdrLen
	for p.proto == 0 || p.proto == 43 || p.proto == 60 {
		if len(data) < 2 {
			p.data = data
			return ReasonExtHeaderLength, 0, false
		}
		hl := (int(data[1]) + 1) * 8
		if len(data) < hl {
			p.data = data
			return ReasonExtHeaderLength, 0, false
		}
		if p.proto == 43 {
			segLeft = int(data[3])
		}
		if segLeft == 0 {
			segPtr += hl
		}
		p.proto = data[0]
		data = data[hl:]
		p.hdrLen += hl
	}

	if p.proto == protoFrag {
		if len(data) < fragHdrLen {
			p.data = data
			return ReasonFragHeaderLength, 0, false
		}
		p.frag = data[:fragHdrLen]
		p.proto = p.frag[0]
		data = data[fragHdrLen:]
		p.hdrLen += fragHdrLen
		of := fragOffFlags(p.frag)
		if of&ip6FragMF != 0 && len(data)&7 != 0 {
			p.data = data
			return ReasonFragmentMisaligned, 0, false
		}
		if int(of&ip6FragMask)+len(data) > 65535 {
			p.data = data
			return ReasonFragmentTooLong, 0, false
		}
	}
	p.data = data

	switch p.proto {
	case protoICMPv6:
		if p.frag != nil && fragOffFlags(p.frag)&(ip6FragMask|ip6FragMF) != 0 {
			return ReasonICMPFragmented, 0, false
		}
		if len(data) < icmpHdrLen {
			return ReasonICMPHeaderLength, 0, false
		}
		p.icmp = data[:icmpHdrLen]
	case protoICMP:
		return ReasonIPv4OnlyProto, 0, false
	}

	if segLeft != 0 {
		return ReasonRoutingHeaderSegmentsLeft, segPtr + 4, false
	}
	return ReasonNone, 0, false
}

// estMTU guesses the MTU of the link that rejected a datagram of the given
// size, using the plateau table of RFC 1191.
func estMTU(tooBig int) int {
	for _, m := range [...]int{65535, 32000, 17914, 8166, 4352, 2002, 1492, 1006, 508, 296} {
		if tooBig > m {
			return m
		}
	}
	return 68
}
