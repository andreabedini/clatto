// Package netconf performs the kernel-side setup around the tun device:
// link state, addresses, routes, policy routing for a CLAT that shares the
// host's address, and forwarding sysctls.
package netconf

import (
	"fmt"
	"net/netip"
)

// Options describes the desired state.
type Options struct {
	Name      string
	Addresses []netip.Prefix
	Routes4   []Route
	Routes6   []Route
	// Forward4 and Forward6 enable net.ipv4.ip_forward and
	// net.ipv6.conf.all.forwarding.
	Forward4 bool
	Forward6 bool
	// Shared, when set, installs the policy routing that sends return
	// traffic for an address the host also owns through the interface.
	Shared *Shared
}

// Route is a route via the interface.
type Route struct {
	Prefix netip.Prefix
	// Metric is the route priority; 0 leaves the kernel default.
	Metric int
	// MTU and AdvMSS are the route metrics of the same name; 0 leaves
	// them unset.
	MTU    int
	AdvMSS int
}

// Shared describes a CLAT that reuses one of the host's own IPv6 addresses
// (the pod IP, typically) instead of a dedicated one. The kernel's local
// table would otherwise deliver translated replies from the PLAT straight
// to the IPv6 stack, so a rule ahead of it sends traffic from the PLAT
// prefix to that address through the interface, via a route in Table.
type Shared struct {
	// Addr is the IPv6 address shared with the host.
	Addr netip.Addr
	// From is the PLAT (NAT64) prefix replies come from.
	From netip.Prefix
	// Table is the routing table holding the route to Addr via the
	// interface.
	Table int
	// Filters narrows the rule to some protocols and destination ports,
	// one rule per filter. Empty means one rule matching everything.
	Filters []Filter
}

// Filter selects traffic by IP protocol and destination port range.
type Filter struct {
	// Proto is the IP protocol number; 0 matches any.
	Proto int
	// Start and End bound the destination port; 0 matches any.
	Start, End uint16
}

func (f Filter) String() string {
	proto := ""
	switch f.Proto {
	case 0:
	case 6:
		proto = "tcp"
	case 17:
		proto = "udp"
	case 58:
		proto = "icmp"
	case 132:
		proto = "sctp"
	default:
		proto = fmt.Sprint(f.Proto)
	}
	switch {
	case proto == "":
		return "all"
	case f.Start == 0:
		return proto
	case f.Start == f.End:
		return fmt.Sprintf("%s/%d", proto, f.Start)
	}
	return fmt.Sprintf("%s/%d-%d", proto, f.Start, f.End)
}

// ruleSpec identifies one policy rule so that rule sets can be compared.
type ruleSpec struct {
	Addr   netip.Addr
	From   netip.Prefix
	Table  int
	Filter Filter
}

func (r ruleSpec) String() string {
	return fmt.Sprintf("from %s to %s %s lookup %d", r.From, r.Addr, r.Filter, r.Table)
}

// ruleSpecs lists the rules a Shared configuration needs; nil for nil.
func (s *Shared) ruleSpecs() []ruleSpec {
	if s == nil {
		return nil
	}
	if len(s.Filters) == 0 {
		return []ruleSpec{{Addr: s.Addr, From: s.From, Table: s.Table}}
	}
	out := make([]ruleSpec, 0, len(s.Filters))
	for _, f := range s.Filters {
		out = append(out, ruleSpec{Addr: s.Addr, From: s.From, Table: s.Table, Filter: f})
	}
	return out
}

// routeKey is what makes a route distinct to the kernel: for IPv6 two
// routes to the same prefix with different metrics coexist.
type routeKey struct {
	Prefix netip.Prefix
	Metric int
}

func (r Route) key() routeKey { return routeKey{r.Prefix, r.Metric} }
