// Package netconf performs the kernel-side setup around the tun device:
// link state, addresses, routes and forwarding sysctls.
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

// Options describes the desired state.
type Options struct {
	Name      string
	Addresses []netip.Prefix
	Routes4   []netip.Prefix
	Routes6   []netip.Prefix
	Sysctl    bool
}

// Update moves the interface from the previously applied options prev to
// next: routes and addresses no longer wanted are removed, new ones added.
// Sysctls are never reverted.
func Update(prev, next Options, log *slog.Logger) error {
	link, err := netlink.LinkByName(next.Name)
	if err != nil {
		return fmt.Errorf("find interface %s: %w", next.Name, err)
	}
	for _, p := range append(missing(next.Routes4, prev.Routes4), missing(next.Routes6, prev.Routes6)...) {
		if err := delRoute(link, p, log); err != nil {
			return err
		}
	}
	for _, p := range missing(next.Addresses, prev.Addresses) {
		if err := netlink.AddrDel(link, &netlink.Addr{IPNet: prefixToIPNet(p)}); err != nil && !errors.Is(err, unix.EADDRNOTAVAIL) {
			return fmt.Errorf("remove address %s from %s: %w", p, next.Name, err)
		}
		log.Info("address removed", "address", p.String(), "interface", next.Name)
	}
	added := next
	added.Addresses = missing(prev.Addresses, next.Addresses)
	added.Routes4 = missing(prev.Routes4, next.Routes4)
	added.Routes6 = missing(prev.Routes6, next.Routes6)
	added.Sysctl = next.Sysctl && !prev.Sysctl
	return Apply(added, log)
}

// missing returns the prefixes in want that are not in have.
func missing(have, want []netip.Prefix) []netip.Prefix {
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

// routeScope is the scope routes are added with: link for IPv4 (as
// "ip route add ... dev" does), universe for IPv6. Deletion must use the
// same scope or the kernel finds no matching route.
func routeScope(p netip.Prefix) netlink.Scope {
	if p.Addr().Is4() {
		return netlink.SCOPE_LINK
	}
	return netlink.SCOPE_UNIVERSE
}

func delRoute(link netlink.Link, p netip.Prefix, log *slog.Logger) error {
	r := &netlink.Route{LinkIndex: link.Attrs().Index, Dst: prefixToIPNet(p), Scope: routeScope(p)}
	err := netlink.RouteDel(r)
	switch {
	case errors.Is(err, unix.ESRCH):
		log.Warn("route already gone", "prefix", p.String(), "interface", link.Attrs().Name)
	case err != nil:
		return fmt.Errorf("remove route %s via %s: %w", p, link.Attrs().Name, err)
	default:
		log.Info("route removed", "prefix", p.String(), "interface", link.Attrs().Name)
	}
	return nil
}

// Apply brings the interface up, assigns addresses, installs routes and
// enables forwarding. It is idempotent.
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
	for _, p := range append(append([]netip.Prefix{}, o.Routes4...), o.Routes6...) {
		if err := addRoute(link, p); err != nil {
			return err
		}
		log.Info("route added", "prefix", p.String(), "interface", o.Name)
	}
	if o.Sysctl {
		for _, s := range []string{"net/ipv4/ip_forward", "net/ipv6/conf/all/forwarding"} {
			if err := writeSysctl(s, "1"); err != nil {
				return err
			}
			log.Info("sysctl set", "name", s, "value", "1")
		}
	}
	return nil
}

func addRoute(link netlink.Link, p netip.Prefix) error {
	r := &netlink.Route{LinkIndex: link.Attrs().Index, Dst: prefixToIPNet(p), Scope: routeScope(p)}
	if err := netlink.RouteReplace(r); err != nil {
		return fmt.Errorf("add route %s via %s: %w", p, link.Attrs().Name, err)
	}
	return nil
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
