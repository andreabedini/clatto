package netconf

import (
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"path/filepath"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// Policy rule priorities used for a shared address. The kernel installs
// the rule for the local table at priority 0; it is moved to
// localRulePriority so that sharedRulePriority runs before it.
const (
	sharedRulePriority = 1
	localRulePriority  = 2
)

// Update moves the interface from the previously applied options prev to
// next: routes, addresses and rules no longer wanted are removed, new ones
// added. Sysctls and the position of the local table rule are never
// reverted.
func Update(prev, next Options, log *slog.Logger) error {
	link, err := netlink.LinkByName(next.Name)
	if err != nil {
		return fmt.Errorf("find interface %s: %w", next.Name, err)
	}
	for _, r := range append(staleRoutes(prev.Routes4, next.Routes4), staleRoutes(prev.Routes6, next.Routes6)...) {
		if err := delRoute(link, r, 0, log); err != nil {
			return err
		}
	}
	for _, p := range missingPrefixes(next.Addresses, prev.Addresses) {
		if err := netlink.AddrDel(link, &netlink.Addr{IPNet: prefixToIPNet(p)}); err != nil && !errors.Is(err, unix.EADDRNOTAVAIL) {
			return fmt.Errorf("remove address %s from %s: %w", p, next.Name, err)
		}
		log.Info("address removed", "address", p.String(), "interface", next.Name)
	}
	if err := removeStaleRules(prev.Shared, next.Shared, log); err != nil {
		return err
	}
	if prev.Shared != nil && (next.Shared == nil || prev.Shared.Addr != next.Shared.Addr || prev.Shared.Table != next.Shared.Table) {
		if err := delRoute(link, Route{Prefix: netip.PrefixFrom(prev.Shared.Addr, 128)}, prev.Shared.Table, log); err != nil {
			return err
		}
	}
	added := next
	added.Addresses = missingPrefixes(prev.Addresses, next.Addresses)
	added.Routes4 = missingRoutes(prev.Routes4, next.Routes4)
	added.Routes6 = missingRoutes(prev.Routes6, next.Routes6)
	added.Forward4 = next.Forward4 && !prev.Forward4
	added.Forward6 = next.Forward6 && !prev.Forward6
	return Apply(added, log)
}

// missingPrefixes returns the prefixes in want that are not in have.
func missingPrefixes(have, want []netip.Prefix) []netip.Prefix {
	set := map[netip.Prefix]bool{}
	for _, p := range have {
		set[p] = true
	}
	var out []netip.Prefix
	for _, p := range want {
		if !set[p] {
			out = append(out, p)
		}
	}
	return out
}

// missingRoutes returns the routes in want that have is not already
// carrying with identical options.
func missingRoutes(have, want []Route) []Route {
	set := map[Route]bool{}
	for _, r := range have {
		set[r] = true
	}
	var out []Route
	for _, r := range want {
		if !set[r] {
			out = append(out, r)
		}
	}
	return out
}

// staleRoutes returns the routes in have whose kernel key (prefix and
// metric) is absent from want. A route whose other options changed is
// replaced in place instead.
func staleRoutes(have, want []Route) []Route {
	set := map[routeKey]bool{}
	for _, r := range want {
		set[r.key()] = true
	}
	var out []Route
	for _, r := range have {
		if !set[r.key()] {
			out = append(out, r)
		}
	}
	return out
}

// routeScope is the scope routes are added with: link for IPv4 (as
// "ip route add ... dev" does), universe for IPv6. Deletion must use the
// same scope or the kernel finds no matching route.
func routeScope(p netip.Prefix) netlink.Scope {
	if p.Addr().Is4() {
		return netlink.SCOPE_LINK
	}
	return netlink.SCOPE_UNIVERSE
}

func kernelRoute(link netlink.Link, r Route, table int) *netlink.Route {
	return &netlink.Route{
		LinkIndex: link.Attrs().Index,
		Dst:       prefixToIPNet(r.Prefix),
		Scope:     routeScope(r.Prefix),
		Table:     table,
		Priority:  r.Metric,
		MTU:       r.MTU,
		AdvMSS:    r.AdvMSS,
	}
}

func routeAttrs(link netlink.Link, r Route, table int) []any {
	attrs := []any{"prefix", r.Prefix.String(), "interface", link.Attrs().Name}
	if table != 0 {
		attrs = append(attrs, "table", table)
	}
	if r.Metric != 0 {
		attrs = append(attrs, "metric", r.Metric)
	}
	if r.MTU != 0 {
		attrs = append(attrs, "mtu", r.MTU)
	}
	if r.AdvMSS != 0 {
		attrs = append(attrs, "advmss", r.AdvMSS)
	}
	return attrs
}

func delRoute(link netlink.Link, r Route, table int, log *slog.Logger) error {
	err := netlink.RouteDel(kernelRoute(link, r, table))
	switch {
	case errors.Is(err, unix.ESRCH):
		log.Warn("route already gone", routeAttrs(link, r, table)...)
	case err != nil:
		return fmt.Errorf("remove route %s via %s: %w", r.Prefix, link.Attrs().Name, err)
	default:
		log.Info("route removed", routeAttrs(link, r, table)...)
	}
	return nil
}

func addRoute(link netlink.Link, r Route, table int, log *slog.Logger) error {
	if err := netlink.RouteReplace(kernelRoute(link, r, table)); err != nil {
		return fmt.Errorf("add route %s via %s: %w", r.Prefix, link.Attrs().Name, err)
	}
	log.Info("route added", routeAttrs(link, r, table)...)
	return nil
}

// Apply brings the interface up, assigns addresses, installs routes and
// rules and enables forwarding. It is idempotent, so it can run again
// after a restart in the same network namespace.
func Apply(o Options, log *slog.Logger) error {
	link, err := netlink.LinkByName(o.Name)
	if err != nil {
		return fmt.Errorf("find interface %s: %w", o.Name, err)
	}
	if err := netlink.LinkSetUp(link); err != nil {
		return fmt.Errorf("set %s up: %w", o.Name, err)
	}
	log.Info("interface up", "name", o.Name, "index", link.Attrs().Index, "mtu", link.Attrs().MTU)

	for _, p := range o.Addresses {
		addr := &netlink.Addr{IPNet: prefixToIPNet(p)}
		if err := netlink.AddrAdd(link, addr); err != nil && !errors.Is(err, unix.EEXIST) {
			return fmt.Errorf("add address %s to %s: %w", p, o.Name, err)
		}
		log.Info("address added", "address", p.String(), "interface", o.Name)
	}
	for _, r := range append(append([]Route{}, o.Routes4...), o.Routes6...) {
		if err := addRoute(link, r, 0, log); err != nil {
			return err
		}
	}
	if o.Shared != nil {
		if err := applyShared(link, o.Shared, log); err != nil {
			return err
		}
	}
	if o.Forward4 {
		if err := setSysctl("net/ipv4/ip_forward", log); err != nil {
			return err
		}
	}
	if o.Forward6 {
		if err := setSysctl("net/ipv6/conf/all/forwarding", log); err != nil {
			return err
		}
	}
	return nil
}

// applyShared installs the policy routing for a shared address: the local
// table rule is demoted below sharedRulePriority, the address is routed
// via the interface in s.Table, and one rule per filter sends traffic
// from the PLAT prefix to the address to that table.
func applyShared(link netlink.Link, s *Shared, log *slog.Logger) error {
	if err := demoteLocalRule(log); err != nil {
		return err
	}
	if err := addRoute(link, Route{Prefix: netip.PrefixFrom(s.Addr, 128)}, s.Table, log); err != nil {
		return err
	}
	for _, spec := range s.ruleSpecs() {
		err := netlink.RuleAdd(spec.rule())
		switch {
		case errors.Is(err, unix.EEXIST):
			log.Info("rule already present", "rule", spec.String(), "priority", sharedRulePriority)
		case err != nil:
			return fmt.Errorf("add IPv6 rule %s: %w", spec, err)
		default:
			log.Info("rule added", "rule", spec.String(), "priority", sharedRulePriority)
		}
	}
	return nil
}

// demoteLocalRule moves the kernel's "from all lookup local" IPv6 rule
// from priority 0 to localRulePriority. It is a no-op when a previous run
// already did it.
func demoteLocalRule(log *slog.Logger) error {
	rules, err := netlink.RuleList(netlink.FAMILY_V6)
	if err != nil {
		return fmt.Errorf("list IPv6 rules: %w", err)
	}
	var atZero, demoted bool
	for _, r := range rules {
		if r.Table != unix.RT_TABLE_LOCAL {
			continue
		}
		switch r.Priority {
		case 0:
			atZero = true
		case localRulePriority:
			demoted = true
		}
	}
	if !demoted {
		r := localRule(localRulePriority)
		if err := netlink.RuleAdd(r); err != nil && !errors.Is(err, unix.EEXIST) {
			return fmt.Errorf("add IPv6 rule for the local table at priority %d: %w", localRulePriority, err)
		}
		log.Info("rule added", "rule", "from all lookup local", "priority", localRulePriority)
	}
	if atZero {
		if err := netlink.RuleDel(localRule(0)); err != nil && !errors.Is(err, unix.ENOENT) {
			return fmt.Errorf("remove IPv6 rule for the local table at priority 0: %w", err)
		}
		log.Info("rule removed", "rule", "from all lookup local", "priority", 0)
	}
	return nil
}

func localRule(priority int) *netlink.Rule {
	r := netlink.NewRule()
	r.Family = netlink.FAMILY_V6
	r.Priority = priority
	r.Table = unix.RT_TABLE_LOCAL
	return r
}

func (spec ruleSpec) rule() *netlink.Rule {
	r := netlink.NewRule()
	r.Family = netlink.FAMILY_V6
	r.Priority = sharedRulePriority
	r.Table = spec.Table
	r.Src = prefixToIPNet(spec.From)
	r.Dst = prefixToIPNet(netip.PrefixFrom(spec.Addr, 128))
	r.IPProto = spec.Filter.Proto
	if spec.Filter.Start != 0 {
		r.Dport = netlink.NewRulePortRange(spec.Filter.Start, spec.Filter.End)
	}
	return r
}

// removeStaleRules deletes the rules prev needed that next does not.
func removeStaleRules(prev, next *Shared, log *slog.Logger) error {
	keep := map[ruleSpec]bool{}
	for _, spec := range next.ruleSpecs() {
		keep[spec] = true
	}
	for _, spec := range prev.ruleSpecs() {
		if keep[spec] {
			continue
		}
		err := netlink.RuleDel(spec.rule())
		switch {
		case errors.Is(err, unix.ENOENT):
			log.Warn("rule already gone", "rule", spec.String(), "priority", sharedRulePriority)
		case err != nil:
			return fmt.Errorf("remove IPv6 rule %s: %w", spec, err)
		default:
			log.Info("rule removed", "rule", spec.String(), "priority", sharedRulePriority)
		}
	}
	return nil
}

// SourceAddress returns the address the kernel would use as the source
// when sending to dst: what "ip route get dst" reports as src.
func SourceAddress(dst netip.Addr) (netip.Addr, error) {
	routes, err := netlink.RouteGet(net.IP(dst.AsSlice()))
	if err != nil {
		return netip.Addr{}, fmt.Errorf("route lookup for %s: %w", dst, err)
	}
	for _, r := range routes {
		if a, ok := netip.AddrFromSlice(r.Src); ok && !a.Unmap().IsUnspecified() {
			return a.Unmap(), nil
		}
	}
	return netip.Addr{}, fmt.Errorf("route lookup for %s reports no source address", dst)
}

func prefixToIPNet(p netip.Prefix) *net.IPNet {
	a := p.Addr()
	if a.Is4() {
		b := a.As4()
		return &net.IPNet{IP: net.IP(b[:]), Mask: net.CIDRMask(p.Bits(), 32)}
	}
	b := a.As16()
	return &net.IPNet{IP: net.IP(b[:]), Mask: net.CIDRMask(p.Bits(), 128)}
}

func setSysctl(name string, log *slog.Logger) error {
	if err := writeSysctl(name, "1"); err != nil {
		return err
	}
	log.Info("sysctl set", "name", name, "value", "1")
	return nil
}

func writeSysctl(name, value string) error {
	path := filepath.Join("/proc/sys", name)
	cur, err := os.ReadFile(path)
	if err == nil && len(cur) > 0 && string(cur[:len(cur)-1]) == value {
		return nil
	}
	if err := os.WriteFile(path, []byte(value), 0o644); err != nil {
		return fmt.Errorf("sysctl %s=%s: %w (grant CAP_NET_ADMIN and a writable /proc/sys, set the sysctl in the pod securityContext, or disable interface.sysctl)", name, value, err)
	}
	return nil
}
