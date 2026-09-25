package addrmap

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"math/bits"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/andreabedini/clatto/internal/netutil"
	"github.com/andreabedini/clatto/internal/xlate"
)

// Default lease times, matching tayga.
const (
	DefaultMinLease = 7440 * time.Second // just over two hours
	DefaultMaxLease = 14 * 24 * time.Hour
)

// dynHost is one dynamic assignment.
type dynHost struct {
	v4      netip.Addr
	v6      netip.Addr
	off     uint32 // offset from the pool base
	lastUse atomic.Int64
	dormant bool
}

// Pool hands out IPv4 addresses from a prefix to IPv6 hosts on demand.
//
// An assignment is "mapped" while it sees traffic and for MinLease after the
// last packet; it then becomes "dormant", keeping its IPv4 address reserved
// so the same host gets it back, until MaxLease after the last packet or
// until the pool runs out and the oldest dormant assignment is reassigned.
type Pool struct {
	prefix   netip.Prefix
	base     uint32
	max      uint32 // host mask; usable offsets are 1..max
	minLease time.Duration
	maxLease time.Duration
	obs      xlate.Observer
	now      func() time.Time
	// reserved reports addresses that must not be handed out because a
	// static entry or the translator's own address claims them.
	reserved func(netip.Addr) bool

	mu      sync.RWMutex
	used    []uint64 // bitmap of allocated offsets
	by4     map[uint32]*dynHost
	mapped  map[netip.Addr]*dynHost
	dormant map[netip.Addr]*dynHost
	dirty   bool
}

// PoolOptions configures a Pool.
type PoolOptions struct {
	MinLease time.Duration
	MaxLease time.Duration
	Observer xlate.Observer
	Now      func() time.Time
}

// NewPool creates a dynamic pool over prefix, which must be between /8 and
// /31.
func NewPool(prefix netip.Prefix, o PoolOptions) (*Pool, error) {
	if !prefix.Addr().Is4() {
		return nil, fmt.Errorf("dynamic pool %s: not an IPv4 prefix", prefix)
	}
	if prefix != prefix.Masked() {
		return nil, fmt.Errorf("dynamic pool %s has host bits set", prefix)
	}
	if prefix.Bits() < 8 || prefix.Bits() > 31 {
		return nil, fmt.Errorf("dynamic pool %s: prefix length must be between 8 and 31", prefix)
	}
	if netutil.ClassifyIPv4(prefix.Addr().As4()) == netutil.IPv4Invalid {
		return nil, fmt.Errorf("dynamic pool %s: reserved address", prefix)
	}
	if o.MinLease <= 0 {
		o.MinLease = DefaultMinLease
	}
	if o.MaxLease <= 0 {
		o.MaxLease = DefaultMaxLease
	}
	if o.Observer == nil {
		o.Observer = xlate.NopObserver{}
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	a := prefix.Addr().As4()
	p := &Pool{
		prefix:   prefix,
		base:     uint32(a[0])<<24 | uint32(a[1])<<16 | uint32(a[2])<<8 | uint32(a[3]),
		max:      uint32(0xffffffff) >> prefix.Bits(),
		minLease: o.MinLease,
		maxLease: o.MaxLease,
		obs:      o.Observer,
		now:      o.Now,
		reserved: func(netip.Addr) bool { return false },
		by4:      map[uint32]*dynHost{},
		mapped:   map[netip.Addr]*dynHost{},
		dormant:  map[netip.Addr]*dynHost{},
	}
	p.used = make([]uint64, (uint64(p.max)+1+63)/64)
	p.used[0] |= 1 // the network address is never handed out
	return p, nil
}

// Prefix returns the pool prefix.
func (p *Pool) Prefix() netip.Prefix { return p.prefix }

// SetObserver replaces the event observer. It must be called before the
// pool sees traffic.
func (p *Pool) SetObserver(obs xlate.Observer) {
	if obs == nil {
		obs = xlate.NopObserver{}
	}
	p.mu.Lock()
	p.obs = obs
	p.mu.Unlock()
}

// Stats describes pool occupancy.
type Stats struct {
	Size    int // addresses available for assignment
	Mapped  int
	Dormant int
}

// Stats returns current occupancy.
func (p *Pool) Stats() Stats {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return Stats{Size: int(p.max), Mapped: len(p.mapped), Dormant: len(p.dormant)}
}

func (p *Pool) addr(off uint32) netip.Addr {
	v := p.base | off
	return netip.AddrFrom4([4]byte{byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)})
}

func (p *Pool) isUsed(off uint32) bool { return p.used[off/64]&(1<<(off%64)) != 0 }
func (p *Pool) setUsed(off uint32)     { p.used[off/64] |= 1 << (off % 64) }
func (p *Pool) clearUsed(off uint32)   { p.used[off/64] &^= 1 << (off % 64) }

// lookup4 finds the mapped IPv6 host for an IPv4 pool address.
func (p *Pool) lookup4(a netip.Addr) (netip.Addr, bool) {
	a4 := a.As4()
	off := (uint32(a4[0])<<24 | uint32(a4[1])<<16 | uint32(a4[2])<<8 | uint32(a4[3])) & p.max
	p.mu.RLock()
	d := p.by4[off]
	p.mu.RUnlock()
	if d == nil || d.dormant {
		return netip.Addr{}, false
	}
	d.lastUse.Store(p.now().Unix())
	return d.v6, true
}

// lookup6 finds or, when allocate is set, creates the assignment for an
// IPv6 host.
func (p *Pool) lookup6(a netip.Addr, allocate bool) (netip.Addr, bool) {
	p.mu.RLock()
	d := p.mapped[a]
	p.mu.RUnlock()
	if d != nil {
		d.lastUse.Store(p.now().Unix())
		return d.v4, true
	}
	if !allocate {
		return netip.Addr{}, false
	}
	return p.assign(a)
}

func (p *Pool) event(reason xlate.Reason, d *dynHost) {
	p.obs.Event(xlate.Event{Kind: xlate.KindDynamic, Reason: reason, Src: d.v4, Dst: d.v6})
}

// assign implements tayga's assign_dynamic.
func (p *Pool) assign(a netip.Addr) (netip.Addr, bool) {
	now := p.now().Unix()
	p.mu.Lock()
	defer p.mu.Unlock()

	if d := p.mapped[a]; d != nil { // raced with another allocation
		d.lastUse.Store(now)
		return d.v4, true
	}
	if d := p.dormant[a]; d != nil {
		p.activate(d, now)
		p.event(xlate.ReasonDynamicReactivated, d)
		return d.v4, true
	}

	// Hash the IPv6 address into a starting offset so that a host tends to
	// get the same address across restarts even without persistence.
	a16 := a.As16()
	var h uint32
	for i := 0; i < 16; i += 4 {
		h += uint32(a16[i])<<24 | uint32(a16[i+1])<<16 | uint32(a16[i+2])<<8 | uint32(a16[i+3])
		for h&^p.max != 0 {
			h = (h & p.max) + (h >> (32 - p.prefix.Bits()))
		}
	}
	for i := uint32(0); i <= p.max; i++ {
		off := (h + i) & p.max
		if off == 0 || p.isUsed(off) {
			continue
		}
		v4 := p.addr(off)
		if p.reserved(v4) {
			continue
		}
		d := &dynHost{v4: v4, v6: a, off: off}
		p.setUsed(off)
		p.by4[off] = d
		p.activate(d, now)
		p.dirty = true
		p.event(xlate.ReasonDynamicAssigned, d)
		return v4, true
	}

	// Pool exhausted: steal the least recently used dormant assignment.
	var oldest *dynHost
	for _, d := range p.dormant {
		if oldest == nil || d.lastUse.Load() < oldest.lastUse.Load() {
			oldest = d
		}
	}
	if oldest == nil {
		p.obs.Event(xlate.Event{Kind: xlate.KindDynamic, Reason: xlate.ReasonDynamicExhausted, Dst: a})
		return netip.Addr{}, false
	}
	delete(p.dormant, oldest.v6)
	oldest.v6 = a
	p.activate(oldest, now)
	p.dirty = true
	p.event(xlate.ReasonDynamicReassigned, oldest)
	return oldest.v4, true
}

// activate moves d to the mapped set. Caller holds mu.
func (p *Pool) activate(d *dynHost, now int64) {
	delete(p.dormant, d.v6)
	d.dormant = false
	d.lastUse.Store(now)
	p.mapped[d.v6] = d
}

// Maintain expires idle assignments. It should be called periodically. It
// reports whether the persisted state needs writing.
func (p *Pool) Maintain() {
	now := p.now().Unix()
	minLease := int64(p.minLease / time.Second)
	maxLease := int64(p.maxLease / time.Second)
	p.mu.Lock()
	defer p.mu.Unlock()
	for v6, d := range p.mapped {
		if d.lastUse.Load()+minLease < now {
			delete(p.mapped, v6)
			d.dormant = true
			p.dormant[v6] = d
			p.event(xlate.ReasonDynamicDormant, d)
		}
	}
	for v6, d := range p.dormant {
		if d.lastUse.Load()+maxLease < now {
			delete(p.dormant, v6)
			delete(p.by4, d.off)
			p.clearUsed(d.off)
			p.dirty = true
			p.event(xlate.ReasonDynamicReleased, d)
		}
	}
}

// Dirty reports whether an assignment was created, reassigned or released
// since the last Save.
func (p *Pool) Dirty() bool {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.dirty
}

// Save writes the assignments to path atomically, in tayga's dynamic.map
// format: "ipv4 ipv6 last-use-unix" per line.
func (p *Pool) Save(path string) error {
	tmp := path + "~~"
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o644)
	if err != nil {
		return err
	}
	p.mu.Lock()
	err = p.write(f)
	if err == nil {
		p.dirty = false
	}
	p.mu.Unlock()
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		os.Remove(tmp)
		return err
	}
	if d, err := os.Open(filepath.Dir(path)); err == nil {
		d.Sync()
		d.Close()
	}
	return nil
}

func (p *Pool) write(w io.Writer) error {
	bw := bufio.NewWriter(w)
	fmt.Fprintf(bw, "###\n### clatto dynamic map database\n### Last written: %s\n###\n\n", p.now().UTC().Format(time.RFC3339))
	hosts := make([]*dynHost, 0, len(p.mapped)+len(p.dormant))
	for _, d := range p.mapped {
		hosts = append(hosts, d)
	}
	for _, d := range p.dormant {
		hosts = append(hosts, d)
	}
	sort.Slice(hosts, func(i, j int) bool { return hosts[i].off < hosts[j].off })
	for _, d := range hosts {
		fmt.Fprintf(bw, "%s\t%s\t%d\n", d.v4, d.v6, d.lastUse.Load())
	}
	return bw.Flush()
}

// Load reads assignments written by Save (or by tayga). Entries whose last
// use is within MinLease become mapped; the rest become dormant. A missing
// file is not an error. Load must be called before the pool is used.
func (p *Pool) Load(path string) (int, error) {
	f, err := os.Open(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return 0, nil
		}
		return 0, err
	}
	defer f.Close()
	return p.read(f)
}

func (p *Pool) read(r io.Reader) (int, error) {
	now := p.now().Unix()
	minLease := int64(p.minLease / time.Second)
	p.mu.Lock()
	defer p.mu.Unlock()
	count := 0
	var future bool
	var loaded []*dynHost
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) == 0 || strings.HasPrefix(fields[0], "#") {
			continue
		}
		if len(fields) != 3 {
			continue
		}
		v4, err1 := netip.ParseAddr(fields[0])
		v6, err2 := netip.ParseAddr(fields[1])
		last, err3 := strconv.ParseInt(fields[2], 10, 64)
		if err1 != nil || err2 != nil || err3 != nil || last <= 0 || !v4.Is4() || !v6.Is6() {
			continue
		}
		if !p.prefix.Contains(v4) || !netutil.ValidIPv6(v6.As16()) {
			continue
		}
		a4 := v4.As4()
		off := (uint32(a4[0])<<24 | uint32(a4[1])<<16 | uint32(a4[2])<<8 | uint32(a4[3])) & p.max
		if off == 0 || p.isUsed(off) || p.reserved(v4) {
			continue
		}
		if _, dup := p.dormant[v6]; dup {
			continue
		}
		if _, dup := p.mapped[v6]; dup {
			continue
		}
		d := &dynHost{v4: v4, v6: v6, off: off, dormant: true}
		d.lastUse.Store(last)
		if last > now {
			future = true
		}
		p.setUsed(off)
		p.by4[off] = d
		p.dormant[v6] = d
		loaded = append(loaded, d)
		count++
	}
	if err := sc.Err(); err != nil {
		return count, err
	}
	for _, d := range loaded {
		if future {
			d.lastUse.Store(now - minLease)
		} else if d.lastUse.Load()+minLease >= now {
			p.activate(d, d.lastUse.Load())
		}
	}
	return count, nil
}

// bitsOnes is used in tests to sanity-check the bitmap.
func (p *Pool) usedCount() int {
	n := 0
	for _, w := range p.used {
		n += bits.OnesCount64(w)
	}
	return n - 1 // network address
}
