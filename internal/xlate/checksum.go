package xlate

import "encoding/binary"

// The checksum helpers work on unfolded 64-bit accumulators of big-endian
// 16-bit words. One's complement addition is associative and commutative, so
// 32-bit words can be added to the accumulator and folded down at the end.

// sum16 adds the big-endian 16-bit words of b to acc. A trailing odd byte is
// treated as the high byte of a final word, as the IP checksum requires.
func sum16(b []byte, acc uint64) uint64 {
	i := 0
	for ; i+8 <= len(b); i += 8 {
		acc += uint64(binary.BigEndian.Uint32(b[i:])) + uint64(binary.BigEndian.Uint32(b[i+4:]))
	}
	for ; i+2 <= len(b); i += 2 {
		acc += uint64(binary.BigEndian.Uint16(b[i:]))
	}
	if i < len(b) {
		acc += uint64(b[i]) << 8
	}
	return acc
}

// fold reduces an accumulator to a 16-bit one's complement sum.
func fold(acc uint64) uint16 {
	acc = (acc >> 32) + (acc & 0xffffffff)
	acc = (acc >> 32) + (acc & 0xffffffff)
	acc = (acc >> 16) + (acc & 0xffff)
	acc = (acc >> 16) + (acc & 0xffff)
	return uint16(acc)
}

// checksum returns the value to store in a checksum field for data b whose
// checksum field is currently zero, given an extra (pseudo-header) sum.
func checksum(b []byte, extra uint64) uint16 {
	return ^fold(sum16(b, extra))
}

// verify reports whether b (including its checksum field) sums to all ones.
func verify(b []byte, extra uint64) bool {
	return fold(sum16(b, extra)) == 0xffff
}

// pseudo4 returns the unfolded IPv4 pseudo-header sum.
func pseudo4(src, dst []byte, length int, proto uint8) uint64 {
	return sum16(src[:4], 0) + sum16(dst[:4], 0) + uint64(length) + uint64(proto)
}

// pseudo6 returns the unfolded IPv6 pseudo-header sum.
func pseudo6(src, dst []byte, length int, nextHeader uint8) uint64 {
	return sum16(src[:16], 0) + sum16(dst[:16], 0) + uint64(uint32(length)>>16) + uint64(uint16(length)) + uint64(nextHeader)
}

// adjust applies RFC 1624 incremental update: old is the current checksum
// field, remove is the unfolded sum of the words being removed and add the
// unfolded sum of the words being added.
func adjust(old uint16, remove, add uint64) uint16 {
	return ^fold(uint64(^old) + uint64(^fold(remove)) + add)
}
