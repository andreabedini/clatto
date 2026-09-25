// Package netutil holds address validation and RFC 6052 helpers shared by the
// translator, the address mapper and the configuration loader.
package netutil

import (
	"errors"
	"net/netip"
)

// ErrInvalidPrefixLen is returned when an RFC 6052 prefix length is not one
// of 32, 40, 48, 56, 64 or 96.
var ErrInvalidPrefixLen = errors.New("RFC 6052 prefix length must be 32, 40, 48, 56, 64 or 96")

// ErrNotEmbedded is returned when an IPv6 address does not carry an IPv4
// address in the position mandated by RFC 6052 (the "u" octet or the suffix
// is not zero).
var ErrNotEmbedded = errors.New("address is not an RFC 6052 embedding")

// WellKnownPrefix is the NAT64 well-known prefix 64:ff9b::/96.
var WellKnownPrefix = netip.MustParsePrefix("64:ff9b::/96")

// IPv4Class classifies an IPv4 address for the purpose of translation.
type IPv4Class uint8

const (
	// IPv4Valid is a globally usable unicast address.
	IPv4Valid IPv4Class = iota
	// IPv4LinkLocal is an address in 169.254.0.0/16. It may appear in packet
	// headers and in explicit maps, but it is never embedded in an RFC 6052
	// prefix.
	IPv4LinkLocal
	// IPv4Invalid is an address that must never be translated: 0.0.0.0/8,
	// 127.0.0.0/8, multicast and the limited broadcast address.
	IPv4Invalid
)

// ClassifyIPv4 mirrors tayga's validate_ip4_addr.
func ClassifyIPv4(a [4]byte) IPv4Class {
	switch {
	case a[0] == 0:
		return IPv4Invalid
	case a[0] == 127:
		return IPv4Invalid
	case a[0] == 169 && a[1] == 254:
		return IPv4LinkLocal
	case a[0]&0xf0 == 0xe0:
		return IPv4Invalid
	case a == [4]byte{255, 255, 255, 255}:
		return IPv4Invalid
	}
	return IPv4Valid
}

// ValidIPv6 mirrors tayga's validate_ip6_addr: it rejects the reserved
// ::/8 block, multicast and link-local unicast, but always accepts the
// well-known prefix.
func ValidIPv6(a [16]byte) bool {
	if a[0] == 0 && a[1] == 0x64 && a[2] == 0xff && a[3] == 0x9b {
		return true
	}
	if a[0] == 0 {
		return false
	}
	if a[0] == 0xff {
		return false
	}
	if a[0] == 0xfe && a[1]&0xc0 == 0x80 {
		return false
	}
	return true
}

// IsPrivateIPv4 reports whether a is in one of the non-global ranges that
// RFC 6052 forbids from being embedded in the well-known prefix.
func IsPrivateIPv4(a [4]byte) bool {
	switch {
	case a[0] == 10: // 10.0.0.0/8
		return true
	case a[0] == 100 && a[1]&0xc0 == 0x40: // 100.64.0.0/10
		return true
	case a[0] == 172 && a[1]&0xf0 == 0x10: // 172.16.0.0/12
		return true
	case a[0] == 192 && a[1] == 0 && a[2] == 2: // 192.0.2.0/24
		return true
	case a[0] == 192 && a[1] == 168: // 192.168.0.0/16
		return true
	case a[0] == 198 && a[1]&0xfe == 0x12: // 198.18.0.0/15
		return true
	case a[0] == 198 && a[1] == 51 && a[2] == 100: // 198.51.100.0/24
		return true
	case a[0] == 203 && a[1] == 0 && a[2] == 113: // 203.0.113.0/24
		return true
	}
	return false
}

// IsWellKnownPrefix reports whether the prefix is exactly 64:ff9b::/96.
func IsWellKnownPrefix(p netip.Prefix) bool {
	return p.Bits() == 96 && p.Addr() == WellKnownPrefix.Addr()
}

// ValidRFC6052PrefixLen reports whether n is a legal RFC 6052 prefix length.
func ValidRFC6052PrefixLen(n int) bool {
	switch n {
	case 32, 40, 48, 56, 64, 96:
		return true
	}
	return false
}

// Embed places the IPv4 address v4 into the IPv6 prefix as described by
// RFC 6052 section 2.2. Bits after the embedded address are zero.
func Embed(prefix [16]byte, prefixLen int, v4 [4]byte) ([16]byte, error) {
	var out [16]byte
	copy(out[:prefixLen/8], prefix[:prefixLen/8])
	switch prefixLen {
	case 32:
		copy(out[4:8], v4[:])
	case 40:
		copy(out[5:8], v4[0:3])
		out[9] = v4[3]
	case 48:
		copy(out[6:8], v4[0:2])
		copy(out[9:11], v4[2:4])
	case 56:
		out[7] = v4[0]
		copy(out[9:12], v4[1:4])
	case 64:
		copy(out[9:13], v4[:])
	case 96:
		copy(out[12:16], v4[:])
	default:
		return out, ErrInvalidPrefixLen
	}
	return out, nil
}

// Extract recovers the IPv4 address embedded in v6 according to the given
// RFC 6052 prefix length. It returns ErrNotEmbedded when the octets that must
// be zero are not.
func Extract(v6 [16]byte, prefixLen int) ([4]byte, error) {
	var out [4]byte
	zero := func(b []byte) bool {
		for _, x := range b {
			if x != 0 {
				return false
			}
		}
		return true
	}
	switch prefixLen {
	case 32:
		if !zero(v6[8:16]) {
			return out, ErrNotEmbedded
		}
		copy(out[:], v6[4:8])
	case 40:
		if v6[8] != 0 || !zero(v6[10:16]) {
			return out, ErrNotEmbedded
		}
		copy(out[0:3], v6[5:8])
		out[3] = v6[9]
	case 48:
		if v6[8] != 0 || !zero(v6[11:16]) {
			return out, ErrNotEmbedded
		}
		copy(out[0:2], v6[6:8])
		copy(out[2:4], v6[9:11])
	case 56:
		if v6[8] != 0 || !zero(v6[12:16]) {
			return out, ErrNotEmbedded
		}
		out[0] = v6[7]
		copy(out[1:4], v6[9:12])
	case 64:
		if v6[8] != 0 || !zero(v6[13:16]) {
			return out, ErrNotEmbedded
		}
		copy(out[:], v6[9:13])
	case 96:
		copy(out[:], v6[12:16])
	default:
		return out, ErrInvalidPrefixLen
	}
	return out, nil
}
