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
	for _, p := range o.Routes4 {
		if err := addRoute(link, p, netlink.SCOPE_LINK); err != nil {
			return err
		}
		log.Info("route added", "prefix", p.String(), "interface", o.Name)
	}
	for _, p := range o.Routes6 {
		if err := addRoute(link, p, netlink.SCOPE_UNIVERSE); err != nil {
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

func addRoute(link netlink.Link, p netip.Prefix, scope netlink.Scope) error {
	r := &netlink.Route{LinkIndex: link.Attrs().Index, Dst: prefixToIPNet(p), Scope: scope}
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
