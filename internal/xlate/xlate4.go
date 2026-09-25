package xlate

import "encoding/binary"

// handleIPv4 is the entry point for packets received from the IPv4 side.
func (t *Translator) handleIPv4(raw []byte, out Emitter) {
	p := &pkt{raw: raw}
	if r := parseIPv4(p); r != ReasonNone {
		t.obs.Event(p.event(KindDrop, r))
		return
	}
	if p.ip[8] == 0 || !verify(p.ip, 0) || p.hdrLen+len(p.data) != ip4TotalLen(p.ip) {
		t.obs.Event(p.event(KindDrop, ReasonIPHeaderInvalid))
		return
	}
	if p.icmp != nil && !verify(p.data, 0) {
		t.obs.Event(p.event(KindDrop, ReasonICMPChecksumInvalid))
		return
	}

	if [4]byte(p.ip[16:20]) == t.local4 {
		if p.proto == protoICMP {
			t.hostICMPv4(p, out)
		} else {
			t.obs.Event(p.event(KindReject, ReasonSelfUnknownProto))
			t.sendICMPv4Error(out, 3, 2, 0, p)
		}
		return
	}

	if p.ip[8] == 1 {
		t.obs.Event(p.event(KindICMP, ReasonTimeExceeded))
		t.sendICMPv4Error(out, 11, 0, 0, p)
		return
	}
	if p.proto != protoICMP || p.icmp[0] == 8 || p.icmp[0] == 0 {
		t.xlate4to6Data(p, out)
	} else {
		t.xlate4to6ICMPError(p, out)
	}
}

// hostICMPv4 answers ICMP addressed to the translator itself.
func (t *Translator) hostICMPv4(p *pkt, out Emitter) {
	switch p.icmp[0] {
	case 8:
		t.obs.Event(p.event(KindSelf, ReasonEchoRequest))
		t.sendICMPv4(out, p.ip[1], p.ip[16:20], p.ip[12:16], 0, p.icmp[1], icmpWord(p.icmp), p.data[icmpHdrLen:])
	default:
		t.obs.Event(p.event(KindSelf, ReasonSelfUnknownICMPType))
	}
}

// sendICMPv4 emits an ICMPv4 message from src to dst.
func (t *Translator) sendICMPv4(out Emitter, tos uint8, src, dst []byte, typ, code uint8, word uint32, payload []byte) {
	n := ipv4HdrLen + icmpHdrLen + len(payload)
	b := out.Packet(n)
	if b == nil {
		return
	}
	h := b[:ipv4HdrLen]
	h[0] = 0x45
	h[1] = tos
	binary.BigEndian.PutUint16(h[2:], uint16(n))
	binary.BigEndian.PutUint16(h[4:], 0)
	binary.BigEndian.PutUint16(h[6:], 0)
	h[8] = 64
	h[9] = protoICMP
	h[10], h[11] = 0, 0
	copy(h[12:16], src[:4])
	copy(h[16:20], dst[:4])
	binary.BigEndian.PutUint16(h[10:], checksum(h, 0))

	ic := b[ipv4HdrLen : ipv4HdrLen+icmpHdrLen]
	ic[0] = typ
	ic[1] = code
	ic[2], ic[3] = 0, 0
	binary.BigEndian.PutUint32(ic[4:], word)
	copy(b[ipv4HdrLen+icmpHdrLen:], payload)
	binary.BigEndian.PutUint16(ic[2:], checksum(b[ipv4HdrLen:], 0))
}

// sendICMPv4Error emits an ICMPv4 error about orig, sourced from the
// translator's own address. Errors are never generated in response to ICMP
// messages other than echo requests.
func (t *Translator) sendICMPv4Error(out Emitter, typ, code uint8, word uint32, orig *pkt) {
	if orig.proto == protoICMP && orig.icmp[0] != 8 {
		return
	}
	n := orig.hdrLen + len(orig.data)
	if max := icmp4MaxLen - ipv4HdrLen - icmpHdrLen; n > max {
		n = max
	}
	t.sendICMPv4(out, 0, t.local4[:], orig.ip[12:16], typ, code, word, orig.raw[:n])
}

// header4to6 fills the 40-byte IPv6 header h from the IPv4 packet p.
func header4to6(p *pkt, h []byte, payloadLen int, src6, dst6 [16]byte) {
	binary.BigEndian.PutUint32(h[0:], 6<<28|uint32(p.ip[1])<<20)
	binary.BigEndian.PutUint16(h[4:], uint16(payloadLen))
	if p.proto == protoICMP {
		h[6] = protoICMPv6
	} else {
		h[6] = p.proto
	}
	h[7] = p.ip[8]
	copy(h[8:24], src6[:])
	copy(h[24:40], dst6[:])
}

// payload4to6 rewrites the transport header of p in place for the new IPv6
// header h (whose addresses must already be set).
func (t *Translator) payload4to6(p *pkt, h []byte) Reason {
	// Non-first fragments carry no transport header.
	if ip4FlagsOff(p.ip)&ip4OffMask != 0 {
		return ReasonNone
	}
	var ckOff int
	switch p.proto {
	case protoICMP:
		// ICMPv4 has no pseudo-header; ICMPv6 does. The type also changes.
		ps := pseudo6(h[8:24], h[24:40], ip4TotalLen(p.ip)-p.hdrLen, protoICMPv6)
		old := binary.BigEndian.Uint16(p.icmp[2:])
		var delta uint64
		if p.icmp[0] == 8 {
			p.icmp[0] = 128
			delta = (128 - 8) << 8
		} else {
			p.icmp[0] = 129
			delta = (129 - 0) << 8
		}
		binary.BigEndian.PutUint16(p.icmp[2:], ^fold(uint64(^old)+ps+delta))
		return ReasonNone
	case protoUDP:
		if len(p.data) < 8 {
			return ReasonUDPHeaderLength
		}
		if binary.BigEndian.Uint16(p.data[6:]) == 0 {
			switch t.cfg.UDPChecksum {
			case UDPChecksumForward:
				return ReasonNone
			case UDPChecksumCalc:
				ck := checksum(p.data, pseudo6(h[8:24], h[24:40], len(p.data), protoUDP))
				if ck == 0 {
					ck = 0xffff
				}
				binary.BigEndian.PutUint16(p.data[6:], ck)
				return ReasonNone
			default:
				return ReasonUDPZeroChecksum
			}
		}
		ckOff = 6
	case protoTCP:
		if len(p.data) < 20 {
			return ReasonTCPHeaderLength
		}
		ckOff = 16
	default:
		return ReasonNone
	}
	old := binary.BigEndian.Uint16(p.data[ckOff:])
	ck := adjust(old, sum16(p.ip[12:20], 0), sum16(h[8:40], 0))
	if p.proto == protoUDP && ck == 0 {
		ck = 0xffff
	}
	binary.BigEndian.PutUint16(p.data[ckOff:], ck)
	return ReasonNone
}

// xlate4to6Data translates a data packet (anything but an ICMP error).
func (t *Translator) xlate4to6Data(p *pkt, out Emitter) {
	fragSize := t.cfg.OfflinkMTU
	if fragSize > t.cfg.MTU {
		fragSize = t.cfg.MTU
	}
	fragSize -= ipv6HdrLen

	dst6, err := t.map4to6(p.ip[16:20])
	if err != nil {
		if err == ErrReject {
			t.obs.Event(p.event(KindReject, ReasonDestinationUnmappable))
			t.sendICMPv4Error(out, 3, 1, 0, p)
		} else {
			t.obs.Event(p.event(KindDrop, ReasonDestinationUnmappable))
		}
		return
	}
	src6, err := t.map4to6(p.ip[12:16])
	if err != nil {
		if err == ErrReject {
			t.obs.Event(p.event(KindReject, ReasonSourceUnmappable))
			t.sendICMPv4Error(out, 3, 10, 0, p)
		} else {
			t.obs.Event(p.event(KindDrop, ReasonSourceUnmappable))
		}
		return
	}

	// We do not respect DF for packets that are already fragmented: the IPv6
	// fragment header costs eight bytes the IPv4 sender did not account for
	// when it sized its fragments to MTU-20.
	fo := ip4FlagsOff(p.ip)
	noFragHdr := false
	if fo&(ip4OffMask|ip4FlagMF) == 0 {
		if fo&ip4FlagDF != 0 {
			if t.cfg.MTU-mtuAdj < p.hdrLen+len(p.data) {
				t.obs.Event(p.event(KindICMP, ReasonPacketTooBig))
				t.sendICMPv4Error(out, 3, 4, uint32(t.cfg.MTU-mtuAdj), p)
				return
			}
			noFragHdr = true
		} else if len(p.data) <= fragSize {
			noFragHdr = true
		}
	}

	var h [ipv6HdrLen]byte
	header4to6(p, h[:], len(p.data), src6, dst6)
	h[7]-- // hop limit

	if r := t.payload4to6(p, h[:]); r != ReasonNone {
		t.obs.Event(p.event(KindDrop, r))
		return
	}

	total := p.hdrLen + len(p.data)
	if noFragHdr {
		b := out.Packet(ipv6HdrLen + len(p.data))
		if b == nil {
			return
		}
		copy(b, h[:])
		copy(b[ipv6HdrLen:], p.data)
		t.obs.Translated(4, total)
		return
	}

	var fh [fragHdrLen]byte
	fh[0] = h[6]
	h[6] = protoFrag
	binary.BigEndian.PutUint32(fh[4:], uint32(ip4Ident(p.ip)))

	off := int(fo&ip4OffMask) * 8
	fragSize = (fragSize - fragHdrLen) &^ 7
	origMF := fo&ip4FlagMF != 0
	data := p.data
	for len(data) > 0 {
		n := fragSize
		if len(data) < n {
			n = len(data)
		}
		binary.BigEndian.PutUint16(h[4:], uint16(fragHdrLen+n))
		flags := uint16(off)
		if len(data) > n || origMF {
			flags |= ip6FragMF
		}
		binary.BigEndian.PutUint16(fh[2:], flags)

		b := out.Packet(ipv6HdrLen + fragHdrLen + n)
		if b == nil {
			return
		}
		copy(b, h[:])
		copy(b[ipv6HdrLen:], fh[:])
		copy(b[ipv6HdrLen+fragHdrLen:], data[:n])
		data = data[n:]
		off += n
	}
	t.obs.Translated(4, total)
}

// ptrTable4to6 maps an ICMPv4 Parameter Problem pointer (byte offset into
// the IPv4 header) to the corresponding IPv6 header offset, or -1.
var ptrTable4to6 = [20]int8{0, 1, 4, 4, -1, -1, -1, -1, 7, 6, -1, -1, 8, 8, 8, 8, 24, 24, 24, 24}

// xlate4to6ICMPError translates an ICMPv4 error message, including the
// embedded packet that caused it.
func (t *Translator) xlate4to6ICMPError(p *pkt, out Emitter) {
	em := &pkt{raw: p.data[icmpHdrLen:]}
	typ, code := p.icmp[0], p.icmp[1]

	if typ == 3 || typ == 11 || typ == 12 {
		// RFC 4884 length field, in 32-bit words.
		if emLen := int(icmpWord(p.icmp)>>14) & 0x3fc; emLen != 0 {
			if len(em.raw) < emLen {
				t.obs.Event(p.event(KindDrop, ReasonEmbeddedTooShort))
				return
			}
			em.raw = em.raw[:emLen]
		}
	}
	if parseIPv4(em) != ReasonNone {
		t.obs.Event(p.event(KindDrop, ReasonEmbeddedParseFailed))
		return
	}
	if em.proto == protoICMP && em.icmp[0] != 8 {
		t.obs.Event(p.event(KindDrop, ReasonICMPErrorOfICMPError))
		return
	}
	if max := mtuMin - 2*ipv6HdrLen - icmpHdrLen; len(em.data) > max {
		em.data = em.data[:max]
	}

	emSrc, err1 := t.map4to6(em.ip[12:16])
	emDst, err2 := t.map4to6(em.ip[16:20])
	if err1 != nil || err2 != nil {
		t.obs.Event(p.event(KindDrop, ReasonEmbeddedUnmappable))
		return
	}
	var inner [ipv6HdrLen]byte
	header4to6(em, inner[:], ip4TotalLen(em.ip)-em.hdrLen, emSrc, emDst)

	var otype, ocode uint8
	var oword uint32
	switch typ {
	case 3: // Destination Unreachable
		otype = 1
		switch code {
		case 0, 1, 5, 6, 7, 8, 11, 12:
			ocode = 0 // No route to destination
		case 2: // Protocol Unreachable
			otype, ocode, oword = 4, 1, 6
		case 3:
			ocode = 4 // Port Unreachable
		case 4: // Fragmentation needed and DF set
			otype, ocode = 2, 0
			mtu := int(icmpWord(p.icmp) & 0xffff)
			if mtu < 68 {
				mtu = estMTU(ip4TotalLen(em.ip))
			}
			mtu += mtuAdj
			if mtu > t.cfg.MTU {
				mtu = t.cfg.MTU
			}
			if mtu < mtuMin {
				mtu = mtuMin
			}
			oword = uint32(mtu)
		case 9, 10, 13, 15:
			ocode = 1 // Administratively prohibited
		default:
			t.obs.Event(p.event(KindDrop, ReasonUnknownUnreachableCode))
			return
		}
	case 11: // Time Exceeded
		otype, ocode = 3, code
	case 12: // Parameter Problem
		if code != 0 && code != 2 {
			t.obs.Event(p.event(KindDrop, ReasonParamProblemInvalidCode))
			return
		}
		ptr := int(icmpWord(p.icmp) >> 24)
		if ptr >= len(ptrTable4to6) {
			t.obs.Event(p.event(KindDrop, ReasonParamProblemInvalidPointer))
			return
		}
		np := ptrTable4to6[ptr]
		if np < 0 {
			t.obs.Event(p.event(KindDrop, ReasonParamProblemUntranslatable))
			return
		}
		otype, ocode, oword = 4, 0, uint32(np)
	default:
		t.obs.Event(p.event(KindDrop, ReasonUnknownICMPType))
		return
	}

	if t.payload4to6(em, inner[:]) != ReasonNone {
		t.obs.Event(p.event(KindDrop, ReasonEmbeddedUntranslatable))
		return
	}

	src6, err := t.map4to6(p.ip[12:16])
	if err != nil {
		// The router that sent the error has no IPv6 mapping; use our own.
		t.obs.Event(p.event(KindICMP, ReasonSynthesisedSource))
		src6 = t.local6
	}
	dst6, err := t.map4to6(p.ip[16:20])
	if err != nil {
		t.obs.Event(p.event(KindDrop, ReasonDestinationUnmappable))
		return
	}

	n := ipv6HdrLen + icmpHdrLen + ipv6HdrLen + len(em.data)
	b := out.Packet(n)
	if b == nil {
		return
	}
	h := b[:ipv6HdrLen]
	header4to6(p, h, n-ipv6HdrLen, src6, dst6)
	h[7]--
	ic := b[ipv6HdrLen : ipv6HdrLen+icmpHdrLen]
	ic[0], ic[1], ic[2], ic[3] = otype, ocode, 0, 0
	binary.BigEndian.PutUint32(ic[4:], oword)
	copy(b[ipv6HdrLen+icmpHdrLen:], inner[:])
	copy(b[ipv6HdrLen+icmpHdrLen+ipv6HdrLen:], em.data)
	binary.BigEndian.PutUint16(ic[2:], checksum(b[ipv6HdrLen:], pseudo6(h[8:24], h[24:40], n-ipv6HdrLen, protoICMPv6)))
	t.obs.Translated(4, p.hdrLen+len(p.data))
}
