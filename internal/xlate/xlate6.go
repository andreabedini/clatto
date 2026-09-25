package xlate

import "encoding/binary"

// handleIPv6 is the entry point for packets received from the IPv6 side.
func (t *Translator) handleIPv6(raw []byte, out Emitter) {
	p := &pkt{raw: raw}
	r, segPtr, silent := parseIPv6(p)
	if r != ReasonNone {
		switch {
		case silent:
			// Multicast source or destination: not ours, not worth noting.
		case r == ReasonRoutingHeaderSegmentsLeft:
			t.obs.Event(p.event(KindReject, r))
			t.sendICMPv6Error(out, 4, 0, uint32(segPtr), p)
		default:
			t.obs.Event(p.event(KindDrop, r))
		}
		return
	}
	if p.ip[7] == 0 || p.hdrLen+len(p.data) != ip6PayloadLen(p.ip) {
		t.obs.Event(p.event(KindDrop, ReasonIPHeaderInvalid))
		return
	}
	if p.icmp != nil && !verify(p.data, pseudo6(p.ip[8:24], p.ip[24:40], len(p.data), protoICMPv6)) {
		t.obs.Event(p.event(KindDrop, ReasonICMPChecksumInvalid))
		return
	}

	if [16]byte(p.ip[24:40]) == t.local6 {
		if p.proto == protoICMPv6 {
			t.hostICMPv6(p, out)
		} else {
			t.obs.Event(p.event(KindReject, ReasonSelfUnknownProto))
			t.sendICMPv6Error(out, 4, 1, 6, p)
		}
		return
	}

	if p.ip[7] == 1 {
		t.obs.Event(p.event(KindICMP, ReasonTimeExceeded))
		t.sendICMPv6Error(out, 3, 0, 0, p)
		return
	}
	if p.proto != protoICMPv6 || p.icmp[0] == 128 || p.icmp[0] == 129 {
		t.xlate6to4Data(p, out)
	} else {
		t.xlate6to4ICMPError(p, out)
	}
}

// hostICMPv6 answers ICMPv6 addressed to the translator itself.
func (t *Translator) hostICMPv6(p *pkt, out Emitter) {
	switch p.icmp[0] {
	case 128:
		t.obs.Event(p.event(KindSelf, ReasonEchoRequest))
		tc := uint8(ip6VerTcFl(p.ip) >> 20)
		t.sendICMPv6(out, tc, p.ip[24:40], p.ip[8:24], 129, p.icmp[1], icmpWord(p.icmp), p.data[icmpHdrLen:])
	default:
		t.obs.Event(p.event(KindSelf, ReasonSelfUnknownICMPType))
	}
}

// sendICMPv6 emits an ICMPv6 message from src to dst.
func (t *Translator) sendICMPv6(out Emitter, tc uint8, src, dst []byte, typ, code uint8, word uint32, payload []byte) {
	n := ipv6HdrLen + icmpHdrLen + len(payload)
	b := out.Packet(n)
	if b == nil {
		return
	}
	h := b[:ipv6HdrLen]
	binary.BigEndian.PutUint32(h[0:], 6<<28|uint32(tc)<<20)
	binary.BigEndian.PutUint16(h[4:], uint16(icmpHdrLen+len(payload)))
	h[6] = protoICMPv6
	h[7] = 64
	copy(h[8:24], src[:16])
	copy(h[24:40], dst[:16])

	ic := b[ipv6HdrLen : ipv6HdrLen+icmpHdrLen]
	ic[0] = typ
	ic[1] = code
	ic[2], ic[3] = 0, 0
	binary.BigEndian.PutUint32(ic[4:], word)
	copy(b[ipv6HdrLen+icmpHdrLen:], payload)
	binary.BigEndian.PutUint16(ic[2:], checksum(b[ipv6HdrLen:], pseudo6(h[8:24], h[24:40], n-ipv6HdrLen, protoICMPv6)))
}

// sendICMPv6Error emits an ICMPv6 error about orig, sourced from the
// translator's own address.
func (t *Translator) sendICMPv6Error(out Emitter, typ, code uint8, word uint32, orig *pkt) {
	if orig.proto == protoICMPv6 && orig.icmp[0] != 128 {
		return
	}
	n := ipv6HdrLen + orig.hdrLen + len(orig.data)
	if max := mtuMin - ipv6HdrLen - icmpHdrLen; n > max {
		n = max
	}
	t.sendICMPv6(out, 0, t.local6[:], orig.ip[8:24], typ, code, word, orig.raw[:n])
}

// header6to4 fills the 20-byte IPv4 header h from the IPv6 packet p. The
// header checksum is left zero.
func header6to4(p *pkt, h []byte, payloadLen int, src4, dst4 [4]byte) {
	h[0] = 0x45
	h[1] = uint8(ip6VerTcFl(p.ip) >> 20)
	binary.BigEndian.PutUint16(h[2:], uint16(ipv4HdrLen+payloadLen))
	switch {
	case p.frag != nil:
		// Carry the fragment over; DF is always clear.
		binary.BigEndian.PutUint16(h[4:], uint16(fragIdent(p.frag)))
		of := fragOffFlags(p.frag)
		fo := of >> 3
		if of&ip6FragMF != 0 {
			fo |= ip4FlagMF
		}
		binary.BigEndian.PutUint16(h[6:], fo)
	case p.hdrLen+payloadLen <= mtuMin:
		// Small enough to be fragmented downstream if needed.
		binary.BigEndian.PutUint16(h[4:], randomIdent())
		binary.BigEndian.PutUint16(h[6:], 0)
	default:
		// Anything larger must trigger Packet Too Big rather than be
		// fragmented, so set DF.
		binary.BigEndian.PutUint16(h[4:], 0)
		binary.BigEndian.PutUint16(h[6:], ip4FlagDF)
	}
	h[8] = p.ip[7]
	if p.proto == protoICMPv6 {
		h[9] = protoICMP
	} else {
		h[9] = p.proto
	}
	h[10], h[11] = 0, 0
	copy(h[12:16], src4[:])
	copy(h[16:20], dst4[:])
}

// payload6to4 rewrites the transport header of p in place for the new IPv4
// header h (whose addresses must already be set).
func (t *Translator) payload6to4(p *pkt, h []byte) Reason {
	if p.frag != nil && fragOffFlags(p.frag)&ip6FragMask != 0 {
		return ReasonNone
	}
	var ckOff int
	switch p.proto {
	case protoICMPv6:
		ps := pseudo6(p.ip[8:24], p.ip[24:40], ip6PayloadLen(p.ip)-p.hdrLen, protoICMPv6)
		old := binary.BigEndian.Uint16(p.icmp[2:])
		var delta uint16
		if p.icmp[0] == 128 {
			p.icmp[0] = 8
			delta = (128 - 8) << 8
		} else {
			p.icmp[0] = 0
			delta = (129 - 0) << 8
		}
		binary.BigEndian.PutUint16(p.icmp[2:], ^fold(uint64(^old)+uint64(^fold(ps))+uint64(^delta)))
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
				ck := checksum(p.data, pseudo4(h[12:16], h[16:20], len(p.data), protoUDP))
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
	ck := adjust(old, sum16(p.ip[8:40], 0), sum16(h[12:20], 0))
	if p.proto == protoUDP && ck == 0 {
		ck = 0xffff
	}
	binary.BigEndian.PutUint16(p.data[ckOff:], ck)
	return ReasonNone
}

// xlate6to4Data translates a data packet (anything but an ICMPv6 error).
func (t *Translator) xlate6to4Data(p *pkt, out Emitter) {
	dst4, err := t.map6to4(p.ip[24:40], false)
	if err != nil {
		if err == ErrReject {
			t.obs.Event(p.event(KindReject, ReasonDestinationUnmappable))
			t.sendICMPv6Error(out, 1, 0, 0, p)
		} else {
			t.obs.Event(p.event(KindDrop, ReasonDestinationUnmappable))
		}
		return
	}
	src4, err := t.map6to4(p.ip[8:24], true)
	if err != nil {
		if err == ErrReject {
			t.obs.Event(p.event(KindReject, ReasonSourceUnmappable))
			t.sendICMPv6Error(out, 1, 5, 0, p)
		} else {
			t.obs.Event(p.event(KindDrop, ReasonSourceUnmappable))
		}
		return
	}

	total := ipv6HdrLen + p.hdrLen + len(p.data)
	if total > t.cfg.MTU {
		t.obs.Event(p.event(KindICMP, ReasonPacketTooBig))
		t.sendICMPv6Error(out, 2, 0, uint32(t.cfg.MTU), p)
		return
	}

	var h [ipv4HdrLen]byte
	header6to4(p, h[:], len(p.data), src4, dst4)
	h[8]-- // TTL

	if r := t.payload6to4(p, h[:]); r != ReasonNone {
		t.obs.Event(p.event(KindDrop, r))
		return
	}
	binary.BigEndian.PutUint16(h[10:], checksum(h[:], 0))

	b := out.Packet(ipv4HdrLen + len(p.data))
	if b == nil {
		return
	}
	copy(b, h[:])
	copy(b[ipv4HdrLen:], p.data)
	t.obs.Translated(6, total)
}

// ptrTable6to4 maps the first eight bytes of an ICMPv6 Parameter Problem
// pointer to IPv4 header offsets, or -1.
var ptrTable6to4 = [8]int8{0, 1, -1, -1, 2, 2, 9, 8}

// xlate6to4ICMPError translates an ICMPv6 error message, including the
// embedded packet that caused it.
func (t *Translator) xlate6to4ICMPError(p *pkt, out Emitter) {
	em := &pkt{raw: p.data[icmpHdrLen:]}
	typ, code := p.icmp[0], p.icmp[1]

	if typ == 1 || typ == 3 {
		// RFC 4884 length field, in 64-bit words.
		if emLen := int(icmpWord(p.icmp)>>21) & 0x7f8; emLen != 0 {
			if len(em.raw) < emLen {
				t.obs.Event(p.event(KindDrop, ReasonEmbeddedTooShort))
				return
			}
			em.raw = em.raw[:emLen]
		}
	}
	if r, _, _ := parseIPv6(em); r != ReasonNone {
		t.obs.Event(p.event(KindDrop, ReasonEmbeddedParseFailed))
		return
	}
	if em.proto == protoICMPv6 && em.icmp[0] != 128 {
		t.obs.Event(p.event(KindDrop, ReasonICMPErrorOfICMPError))
		return
	}
	if max := icmp4MaxLen - 2*ipv4HdrLen - icmpHdrLen; len(em.data) > max {
		em.data = em.data[:max]
	}

	var otype, ocode uint8
	var oword uint32
	switch typ {
	case 1: // Destination Unreachable
		otype = 3
		switch code {
		case 0, 2, 3:
			ocode = 1 // Host Unreachable
		case 1:
			ocode = 10 // Administratively prohibited
		case 4:
			ocode = 3 // Port Unreachable
		default:
			t.obs.Event(p.event(KindDrop, ReasonUnknownUnreachableCode))
			return
		}
	case 2: // Packet Too Big
		otype, ocode = 3, 4
		mtu := int(icmpWord(p.icmp))
		if mtu < 68 {
			t.obs.Event(p.event(KindDrop, ReasonNoMTUInPacketTooBig))
			return
		}
		if mtu > t.cfg.MTU {
			mtu = t.cfg.MTU
		}
		oword = uint32(mtu - mtuAdj)
	case 3: // Time Exceeded
		otype, ocode = 11, code
	case 4: // Parameter Problem
		switch code {
		case 0: // Erroneous header field
			ptr := int(icmpWord(p.icmp))
			var np int
			switch {
			case ptr > 39:
				t.obs.Event(p.event(KindDrop, ReasonParamProblemInvalidPointer))
				return
			case ptr > 23:
				np = 16
			case ptr > 7:
				np = 12
			default:
				np = int(ptrTable6to4[ptr])
			}
			if np < 0 {
				t.obs.Event(p.event(KindDrop, ReasonParamProblemUntranslatable))
				return
			}
			otype, ocode, oword = 12, 0, uint32(np)<<24
		case 1: // Unrecognised next header
			otype, ocode = 3, 2
		default:
			t.obs.Event(p.event(KindDrop, ReasonParamProblemInvalidCode))
			return
		}
	default:
		t.obs.Event(p.event(KindDrop, ReasonUnknownICMPType))
		return
	}

	emSrc, err1 := t.map6to4(em.ip[8:24], false)
	emDst, err2 := t.map6to4(em.ip[24:40], false)
	if err1 != nil || err2 != nil {
		t.obs.Event(p.event(KindDrop, ReasonEmbeddedUnmappable))
		return
	}
	var inner [ipv4HdrLen]byte
	header6to4(em, inner[:], ip6PayloadLen(em.ip)-em.hdrLen, emSrc, emDst)
	if t.payload6to4(em, inner[:]) != ReasonNone {
		t.obs.Event(p.event(KindDrop, ReasonEmbeddedUntranslatable))
		return
	}
	binary.BigEndian.PutUint16(inner[10:], checksum(inner[:], 0))

	src4, err := t.map6to4(p.ip[8:24], false)
	if err != nil {
		t.obs.Event(p.event(KindICMP, ReasonSynthesisedSource))
		src4 = t.local4
	}
	dst4, err := t.map6to4(p.ip[24:40], false)
	if err != nil {
		t.obs.Event(p.event(KindDrop, ReasonDestinationUnmappable))
		return
	}

	n := ipv4HdrLen + icmpHdrLen + ipv4HdrLen + len(em.data)
	b := out.Packet(n)
	if b == nil {
		return
	}
	h := b[:ipv4HdrLen]
	header6to4(p, h, n-ipv4HdrLen, src4, dst4)
	h[8]--
	binary.BigEndian.PutUint16(h[10:], checksum(h, 0))
	ic := b[ipv4HdrLen : ipv4HdrLen+icmpHdrLen]
	ic[0], ic[1], ic[2], ic[3] = otype, ocode, 0, 0
	binary.BigEndian.PutUint32(ic[4:], oword)
	copy(b[ipv4HdrLen+icmpHdrLen:], inner[:])
	copy(b[ipv4HdrLen+icmpHdrLen+ipv4HdrLen:], em.data)
	binary.BigEndian.PutUint16(ic[2:], checksum(b[ipv4HdrLen:], 0))
	t.obs.Translated(6, ipv6HdrLen+p.hdrLen+len(p.data))
}
