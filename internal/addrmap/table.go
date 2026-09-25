// Package addrmap maps addresses between IPv4 and IPv6 using static maps, an
// RFC 6052 prefix and an optional dynamic pool, following tayga's rules.
package addrmap

import (
	"errors"
	"fmt"
	"net/netip"
	"sort"

	"github.com/andreabedini/clatto/internal/netutil"
	"github.com/andreabedini/clatto/internal/xlate"
)

// Kind is the type of a mapping entry.
type Kind uint8

const (
	// KindStatic is an explicit IPv4 prefix to IPv6 prefix map of equal
	// host-part size.
	KindStatic Kind = iota
	// KindRFC6052 is the NAT64 prefix; IPv4 addresses are embedded in it.
	KindRFC6052
	// KindDynamicPool is the IPv4 pool from which dynamic hosts are drawn.
	KindDynamicPool
	// KindDynamicHost is a runtime IPv6 host to IPv4 address assignment.
	KindDynamicHost
)

func (k Kind) String() string {
	switch k {
	case KindStatic:
		return "static"
	case KindRFC6052:
		return "rfc6052"
	case KindDynamicPool:
		return "dynamic-pool"
	case KindDynamicHost:
		return "dynamic-host"
	}
	return "unknown"
}

// Entry is one mapping. For a static entry V4 and V6 are prefixes with the
// same number of host bits. For the RFC 6052 entry V4 is 0.0.0.0/0. For the
// pool V6 is unset.
type Entry struct {
	Kind Kind
	V4   netip.Prefix
	V6   netip.Prefix
	// v4Only marks the translator's own address when its IPv6 side is
	// derived from the NAT64 prefix: the IPv4 side is a static host, the
	// IPv6 side is reached through the prefix.
	v4Only bool
}

func (e Entry) String() string {
	switch e.Kind {
	case KindRFC6052:
		return fmt.Sprintf("prefix %s", e.V6)
	case KindDynamicPool:
		return fmt.Sprintf("dynamic-pool %s", e.V4)
	}
	return fmt.Sprintf("%s %s <-> %s", e.Kind, e.V4, e.V6)
}

// Table is an immutable set of static mappings plus an optional dynamic
// pool. It implements xlate.Mapper and is safe for concurrent use.
type Table struct {
	wkpfStrict bool
	prefix     *Entry // the RFC 6052 entry, or nil
	hosts4     map[netip.Addr]*Entry
	hosts6     map[netip.Addr]*Entry
	nets4      []*Entry // longest prefix first; includes the pool entry
	nets6      []*Entry // longest prefix first; includes the RFC 6052 entry
	pool       *Pool
	poolEntry  *Entry
}

// Builder accumulates entries and validates them into a Table.
type Builder struct {
	wkpfStrict bool
	entries    []*Entry
	pool       *Pool
	err        error
}

// NewBuilder starts a Table definition. wkpfStrict enables the RFC 6052
// restriction on translating private IPv4 addresses through 64:ff9b::/96.
func NewBuilder(wkpfStrict bool) *Builder {
	return &Builder{wkpfStrict: wkpfStrict}
}

// ErrConflict is wrapped by errors describing overlapping entries.
var ErrConflict = errors.New("mapping conflict")

// AddPrefix sets the NAT64 prefix.
func (b *Builder) AddPrefix(p netip.Prefix) error {
	if !p.Addr().Is6() || p.Addr().Is4In6() {
		return fmt.Errorf("prefix %s is not IPv6", p)
	}
	if !netutil.ValidRFC6052PrefixLen(p.Bits()) {
		return fmt.Errorf("prefix %s: %w", p, netutil.ErrInvalidPrefixLen)
	}
	if p != p.Masked() {
		return fmt.Errorf("prefix %s has host bits set", p)
	}
	if !netutil.ValidIPv6(p.Addr().As16()) {
		return fmt.Errorf("prefix %s is in a reserved range", p)
	}
	for _, e := range b.entries {
		if e.Kind == KindRFC6052 {
			return fmt.Errorf("%w: duplicate prefix %s", ErrConflict, p)
		}
	}
	b.entries = append(b.entries, &Entry{Kind: KindRFC6052, V4: netip.PrefixFrom(netip.IPv4Unspecified(), 0), V6: p})
	return nil
}

// AddStatic adds a static map. Both prefixes must have the same number of
// host bits (32-v4.Bits() == 128-v6.Bits()).
func (b *Builder) AddStatic(v4, v6 netip.Prefix) error {
	if !v4.Addr().Is4() {
		return fmt.Errorf("map %s: not an IPv4 prefix", v4)
	}
	if !v6.Addr().Is6() || v6.Addr().Is4In6() {
		return fmt.Errorf("map %s: not an IPv6 prefix", v6)
	}
	if 32-v4.Bits() != 128-v6.Bits() {
		return fmt.Errorf("map %s <-> %s: subnets must be the same size", v4, v6)
	}
	if v4 != v4.Masked() || v6 != v6.Masked() {
		return fmt.Errorf("map %s <-> %s: host bits set", v4, v6)
	}
	if netutil.ClassifyIPv4(v4.Addr().As4()) == netutil.IPv4Invalid {
		return fmt.Errorf("map %s: reserved IPv4 address", v4)
	}
	if !netutil.ValidIPv6(v6.Addr().As16()) {
		return fmt.Errorf("map %s: reserved IPv6 address", v6)
	}
	b.entries = append(b.entries, &Entry{Kind: KindStatic, V4: v4, V6: v6})
	return nil
}

// AddSelf adds the translator's own addresses. When v6Derived is set the
// IPv6 address lies inside the NAT64 prefix and only the IPv4 side is
// registered.
func (b *Builder) AddSelf(v4, v6 netip.Addr, v6Derived bool) error {
	p4 := netip.PrefixFrom(v4, 32)
	p6 := netip.PrefixFrom(v6, 128)
	if !v6Derived {
		return b.AddStatic(p4, p6)
	}
	if !v4.Is4() || netutil.ClassifyIPv4(v4.As4()) == netutil.IPv4Invalid {
		return fmt.Errorf("ipv4 address %s is reserved", v4)
	}
	b.entries = append(b.entries, &Entry{Kind: KindStatic, V4: p4, V6: p6, v4Only: true})
	return nil
}

// SetPool attaches a dynamic pool.
func (b *Builder) SetPool(p *Pool) error {
	if b.pool != nil {
		return fmt.Errorf("%w: duplicate dynamic pool", ErrConflict)
	}
	b.pool = p
	b.entries = append(b.entries, &Entry{Kind: KindDynamicPool, V4: p.prefix})
	return nil
}

// Build validates the entries and produces the Table.
func (b *Builder) Build() (*Table, error) {
	t := &Table{
		wkpfStrict: b.wkpfStrict,
		hosts4:     map[netip.Addr]*Entry{},
		hosts6:     map[netip.Addr]*Entry{},
		pool:       b.pool,
	}
	// Longest prefix first; stable so that conflicts are reported in
	// definition order.
	entries := append([]*Entry(nil), b.entries...)
	sort.SliceStable(entries, func(i, j int) bool { return entries[i].V4.Bits() > entries[j].V4.Bits() })

	var v6s []*Entry
	for _, e := range entries {
		switch e.Kind {
		case KindRFC6052:
			t.prefix = e
			v6s = append(v6s, e)
			t.nets4 = append(t.nets4, e)
		case KindDynamicPool:
			t.poolEntry = e
			t.nets4 = append(t.nets4, e)
		case KindStatic:
			// IPv4 side: only exact duplicates conflict (longest match
			// disambiguates overlaps, as in tayga).
			if e.V4.Bits() == 32 {
				if _, dup := t.hosts4[e.V4.Addr()]; dup {
					return nil, fmt.Errorf("%w: IPv4 address %s mapped twice", ErrConflict, e.V4.Addr())
				}
				t.hosts4[e.V4.Addr()] = e
			} else {
				for _, o := range t.nets4 {
					if o.Kind != KindDynamicPool && o.V4 == e.V4 {
						return nil, fmt.Errorf("%w: IPv4 prefix %s mapped twice", ErrConflict, e.V4)
					}
				}
				t.nets4 = append(t.nets4, e)
			}
			if !e.v4Only {
				v6s = append(v6s, e)
			}
		}
	}
	if t.poolEntry != nil {
		for _, o := range t.nets4 {
			if o != t.poolEntry && o.Kind == KindStatic && o.V4 == t.poolEntry.V4 {
				return nil, fmt.Errorf("%w: dynamic pool %s is also a static map", ErrConflict, o.V4)
			}
		}
	}
	// IPv6 side: any overlap is a conflict.
	sort.SliceStable(v6s, func(i, j int) bool { return v6s[i].V6.Bits() > v6s[j].V6.Bits() })
	for i, e := range v6s {
		for _, o := range v6s[:i] {
			if o.V6.Overlaps(e.V6) {
				return nil, fmt.Errorf("%w: %s overlaps %s", ErrConflict, e, o)
			}
		}
		if e.Kind == KindStatic && e.V6.Bits() == 128 {
			t.hosts6[e.V6.Addr()] = e
		} else {
			t.nets6 = append(t.nets6, e)
		}
	}
	if t.pool != nil {
		t.pool.reserved = func(a netip.Addr) bool { return t.lookup4(a) != t.poolEntry }
	}
	return t, nil
}

// Prefix returns the NAT64 prefix, if configured.
func (t *Table) Prefix() (netip.Prefix, bool) {
	if t.prefix == nil {
		return netip.Prefix{}, false
	}
	return t.prefix.V6, true
}

// Pool returns the dynamic pool, if configured.
func (t *Table) Pool() *Pool { return t.pool }

// Entries returns all static entries, the prefix and the pool, for display
// and for deriving routes.
func (t *Table) Entries() []Entry {
	var out []Entry
	seen := map[*Entry]bool{}
	add := func(e *Entry) {
		if !seen[e] {
			seen[e] = true
			out = append(out, *e)
		}
	}
	for _, e := range t.hosts4 {
		add(e)
	}
	for _, e := range t.nets4 {
		add(e)
	}
	for _, e := range t.hosts6 {
		add(e)
	}
	for _, e := range t.nets6 {
		add(e)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Kind != out[j].Kind {
			return out[i].Kind < out[j].Kind
		}
		return out[i].V4.Addr().Less(out[j].V4.Addr())
	})
	return out
}

// lookup4 finds the longest-matching static entry for a. Dynamic hosts are
// not consulted; callers check the pool separately.
func (t *Table) lookup4(a netip.Addr) *Entry {
	if e, ok := t.hosts4[a]; ok {
		return e
	}
	for _, e := range t.nets4 {
		if e.V4.Contains(a) {
			return e
		}
	}
	return nil
}

func (t *Table) lookup6(a netip.Addr) *Entry {
	if e, ok := t.hosts6[a]; ok {
		return e
	}
	for _, e := range t.nets6 {
		if e.V6.Contains(a) {
			return e
		}
	}
	return nil
}

// MapIPv4ToIPv6 implements xlate.Mapper.
func (t *Table) MapIPv4ToIPv6(a netip.Addr) (netip.Addr, error) {
	e := t.lookup4(a)
	if e == nil {
		return netip.Addr{}, xlate.ErrReject
	}
	switch e.Kind {
	case KindStatic:
		return joinStatic6(e, a), nil
	case KindRFC6052:
		return t.embed(a, e.V6)
	case KindDynamicPool:
		if v6, ok := t.pool.lookup4(a); ok {
			return v6, nil
		}
		return netip.Addr{}, xlate.ErrReject
	}
	return netip.Addr{}, xlate.ErrDrop
}

// MapIPv6ToIPv4 implements xlate.Mapper.
func (t *Table) MapIPv6ToIPv4(a netip.Addr, allocate bool) (netip.Addr, error) {
	e := t.lookup6(a)
	if e == nil {
		if t.pool == nil {
			return netip.Addr{}, xlate.ErrReject
		}
		v4, ok := t.pool.lookup6(a, allocate)
		if !ok {
			return netip.Addr{}, xlate.ErrReject
		}
		return v4, nil
	}
	switch e.Kind {
	case KindStatic:
		return joinStatic4(e, a), nil
	case KindRFC6052:
		v4b, err := netutil.Extract(a.As16(), e.V6.Bits())
		if err != nil {
			return netip.Addr{}, xlate.ErrDrop
		}
		if netutil.ClassifyIPv4(v4b) != netutil.IPv4Valid {
			return netip.Addr{}, xlate.ErrDrop
		}
		if t.wkpfStrict && netutil.IsWellKnownPrefix(e.V6) && netutil.IsPrivateIPv4(v4b) {
			return netip.Addr{}, xlate.ErrReject
		}
		v4 := netip.AddrFrom4(v4b)
		// Hairpin: the embedded IPv4 address must itself map back through
		// the prefix, not through a static map or the pool.
		if t.lookup4(v4) != e {
			return netip.Addr{}, xlate.ErrDrop
		}
		return v4, nil
	}
	return netip.Addr{}, xlate.ErrDrop
}

func (t *Table) embed(a netip.Addr, prefix netip.Prefix) (netip.Addr, error) {
	a4 := a.As4()
	if netutil.ClassifyIPv4(a4) != netutil.IPv4Valid {
		return netip.Addr{}, xlate.ErrDrop
	}
	if t.wkpfStrict && netutil.IsWellKnownPrefix(prefix) && netutil.IsPrivateIPv4(a4) {
		return netip.Addr{}, xlate.ErrReject
	}
	out, err := netutil.Embed(prefix.Addr().As16(), prefix.Bits(), a4)
	if err != nil {
		return netip.Addr{}, xlate.ErrDrop
	}
	return netip.AddrFrom16(out), nil
}

// joinStatic6 combines the IPv6 side of a static entry with the host bits
// of a.
func joinStatic6(e *Entry, a netip.Addr) netip.Addr {
	if e.V4.Bits() == 32 {
		return e.V6.Addr()
	}
	hostMask := uint32(0xffffffff) >> e.V4.Bits()
	a4 := a.As4()
	host := (uint32(a4[0])<<24 | uint32(a4[1])<<16 | uint32(a4[2])<<8 | uint32(a4[3])) & hostMask
	v6 := e.V6.Addr().As16()
	v6[12] |= byte(host >> 24)
	v6[13] |= byte(host >> 16)
	v6[14] |= byte(host >> 8)
	v6[15] |= byte(host)
	return netip.AddrFrom16(v6)
}

// joinStatic4 combines the IPv4 side of a static entry with the host bits
// of a.
func joinStatic4(e *Entry, a netip.Addr) netip.Addr {
	if e.V6.Bits() == 128 {
		return e.V4.Addr()
	}
	hostMask := uint32(0xffffffff) >> e.V4.Bits()
	a6 := a.As16()
	host := (uint32(a6[12])<<24 | uint32(a6[13])<<16 | uint32(a6[14])<<8 | uint32(a6[15])) & hostMask
	v4 := e.V4.Addr().As4()
	v4[0] |= byte(host >> 24)
	v4[1] |= byte(host >> 16)
	v4[2] |= byte(host >> 8)
	v4[3] |= byte(host)
	return netip.AddrFrom4(v4)
}
