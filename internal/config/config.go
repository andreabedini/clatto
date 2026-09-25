// Package config defines clatto's configuration, loads it from YAML and the
// environment, and resolves it into the objects the daemon runs on.
package config

import (
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/andreabedini/clatto/internal/addrmap"
	"github.com/andreabedini/clatto/internal/netconf"
	"github.com/andreabedini/clatto/internal/netutil"
	"github.com/andreabedini/clatto/internal/xlate"
)

// Defaults.
const (
	DefaultInterface  = "clat0"
	DefaultMTU        = 1500
	DefaultOfflinkMTU = 1280
	DefaultHTTPListen = ":6464"
	DefaultConfigPath = "/etc/clatto/config.yaml"
	EnvPrefix         = "CLATTO_"
	// DefaultCLATTable is the policy routing table a shared-address CLAT
	// uses ("clat").
	DefaultCLATTable = 0xc1a7
)

// Reserved routing tables (rtnetlink's RT_TABLE_*).
const (
	rtTableDefault = 253
	rtTableMain    = 254
	rtTableLocal   = 255
)

// Default addresses of a CLAT: the host side is the RFC 7335 well-known
// address, the translator takes the next one.
var (
	DefaultCLATHostIPv4       = netip.MustParseAddr("192.0.0.1")
	DefaultCLATTranslatorIPv4 = netip.MustParseAddr("192.0.0.2")
)

// Config is the user-facing configuration. Zero values mean "default".
type Config struct {
	Interface   Interface    `yaml:"interface"`
	IPv4Address netip.Addr   `yaml:"ipv4_address"`
	IPv6Address netip.Addr   `yaml:"ipv6_address"`
	Prefix      netip.Prefix `yaml:"prefix"`
	WKPFStrict  *bool        `yaml:"wkpf_strict,omitempty"`
	Maps        []Map        `yaml:"maps,omitempty"`
	DynamicPool *DynamicPool `yaml:"dynamic_pool,omitempty"`
	CLAT        *CLAT        `yaml:"clat,omitempty"`
	UDPChecksum string       `yaml:"udp_checksum,omitempty"`
	OfflinkMTU  int          `yaml:"offlink_mtu,omitempty"`
	Log         Log          `yaml:"log,omitempty"`
	HTTP        HTTP         `yaml:"http,omitempty"`
}

// CLAT makes clatto a customer-side translator (RFC 6877) that shares one
// of the host's own IPv6 addresses instead of using a dedicated one. This
// is the only option on a host with a single routed address, such as a
// pod. The host's IPv4 address is assigned to the interface and mapped to
// the shared IPv6 address, an IPv4 default route via the interface is
// installed instead of a route for the prefix, and policy routing sends
// replies from the prefix to the shared address through the interface
// ahead of the kernel's local table. IPv4 forwarding is not needed.
type CLAT struct {
	// IPv6Address is the address shared with the host: an IPv6 address,
	// or "auto" (the default) for the source address the kernel picks to
	// reach the prefix.
	IPv6Address string `yaml:"ipv6_address,omitempty"`
	// IPv4Address is the host's IPv4 address. Default 192.0.0.1.
	IPv4Address netip.Addr `yaml:"ipv4_address"`
	// Ports limits the traffic from the prefix that is translated back to
	// IPv4: "tcp/N-M", "udp/N-M", "tcp/N" or "icmp", one rule each. Empty
	// means everything from the prefix to the shared address, which also
	// catches replies to the host's own connections to NAT64-synthesised
	// addresses.
	Ports []string `yaml:"ports,omitempty"`
	// Table is the policy routing table. Default 0xc1a7.
	Table int `yaml:"table,omitempty"`
}

// Route is a route via the interface: in YAML either a bare prefix or a
// mapping with prefix and options.
type Route struct {
	Prefix netip.Prefix `yaml:"prefix"`
	Metric int          `yaml:"metric,omitempty"`
	MTU    int          `yaml:"mtu,omitempty"`
	AdvMSS int          `yaml:"advmss,omitempty"`
}

// UnmarshalYAML accepts "0.0.0.0/0" as well as {prefix: 0.0.0.0/0, metric: 2048}.
func (r *Route) UnmarshalYAML(n *yaml.Node) error {
	if n.Kind == yaml.ScalarNode {
		p, err := parseAddrOrPrefix(n.Value)
		if err != nil {
			return fmt.Errorf("line %d: route: %w", n.Line, err)
		}
		*r = Route{Prefix: p}
		return nil
	}
	if n.Kind != yaml.MappingNode {
		return fmt.Errorf("line %d: route must be a prefix or a mapping", n.Line)
	}
	for i := 0; i+1 < len(n.Content); i += 2 {
		switch k := n.Content[i].Value; k {
		case "prefix", "metric", "mtu", "advmss":
		default:
			return fmt.Errorf("line %d: route: unknown field %q", n.Content[i].Line, k)
		}
	}
	type plain Route
	var p plain
	if err := n.Decode(&p); err != nil {
		return err
	}
	if !p.Prefix.IsValid() {
		return fmt.Errorf("line %d: route: prefix is required", n.Line)
	}
	*r = Route(p)
	return nil
}

// MarshalYAML renders a route without options as a bare prefix.
func (r Route) MarshalYAML() (any, error) {
	if r.Metric == 0 && r.MTU == 0 && r.AdvMSS == 0 {
		return r.Prefix.String(), nil
	}
	type plain Route
	return plain(r), nil
}

func (r Route) netconf() netconf.Route {
	return netconf.Route{Prefix: r.Prefix.Masked(), Metric: r.Metric, MTU: r.MTU, AdvMSS: r.AdvMSS}
}

// Interface describes the tun device and how much of the surrounding
// network setup the daemon performs.
type Interface struct {
	Name string `yaml:"name"`
	MTU  int    `yaml:"mtu,omitempty"`
	// Configure enables all kernel-side setup: link up, addresses, routes
	// and sysctls. Default true.
	Configure *bool `yaml:"configure,omitempty"`
	// Addresses are assigned to the interface.
	Addresses []netip.Prefix `yaml:"addresses,omitempty"`
	// Routes are installed via the interface in addition to the automatic
	// ones; a route here replaces the automatic route for the same prefix.
	Routes []Route `yaml:"routes,omitempty"`
	// AutoRoutes routes what the translator receives via the interface:
	// the static maps' IPv4 side, the dynamic pool, its own addresses and
	// the prefix (in CLAT mode: an IPv4 default route instead of the
	// prefix). The IPv6 side of a static map is a real host and is not
	// routed. Default true.
	AutoRoutes *bool `yaml:"auto_routes,omitempty"`
	// Sysctl enables IPv4 and IPv6 forwarding (in CLAT mode: IPv6 only).
	// Default true.
	Sysctl *bool `yaml:"sysctl,omitempty"`
}

// Map is one static mapping. Either side may carry a prefix length; the
// two sides must have the same number of host bits.
type Map struct {
	IPv4 string `yaml:"ipv4"`
	IPv6 string `yaml:"ipv6"`
}

// DynamicPool configures on-demand IPv4 assignment.
type DynamicPool struct {
	Prefix    netip.Prefix  `yaml:"prefix"`
	StateFile string        `yaml:"state_file,omitempty"`
	MinLease  time.Duration `yaml:"min_lease,omitempty"`
	MaxLease  time.Duration `yaml:"max_lease,omitempty"`
}

// Log configures logging.
type Log struct {
	Level  string `yaml:"level,omitempty"`  // debug, info, warn, error
	Format string `yaml:"format,omitempty"` // json, text
	// Packets lists packet event kinds to log: drop, reject, icmp, self,
	// dynamic. Metrics count them regardless.
	Packets []string `yaml:"packets,omitempty"`
}

// HTTP configures the health and metrics listener.
type HTTP struct {
	// Listen is the address; empty means the default, "off" disables.
	Listen string `yaml:"listen,omitempty"`
	// Admin enables the endpoints that change configuration at runtime.
	// Off by default: the listener is usually reachable from the network.
	Admin bool `yaml:"admin,omitempty"`
}

// Resolved is a validated configuration with derived objects.
type Resolved struct {
	Config Config
	Xlate  xlate.Config
	Table  *addrmap.Table
	Pool   *addrmap.Pool
	// Addresses are assigned to the interface.
	Addresses []netip.Prefix
	// Routes4 and Routes6 are the routes to install via the interface.
	Routes4 []netconf.Route
	Routes6 []netconf.Route
	// Shared is the policy routing of a CLAT sharing the host's address;
	// nil otherwise.
	Shared *netconf.Shared
	// Warnings are non-fatal findings worth logging.
	Warnings []string
	// LogLevel, LogJSON and PacketKinds are the parsed log settings.
	LogLevel    slog.Level
	LogJSON     bool
	PacketKinds map[xlate.Kind]bool
	HTTPListen  string
}

// Configure reports whether kernel-side setup is enabled.
func (r *Resolved) Configure() bool { return boolOr(r.Config.Interface.Configure, true) }

// Sysctl reports whether forwarding sysctls should be set.
func (r *Resolved) Sysctl() bool { return r.Configure() && boolOr(r.Config.Interface.Sysctl, true) }

// Forward4 reports whether IPv4 forwarding should be enabled. A CLAT only
// ever delivers IPv4 packets locally, so it needs none.
func (r *Resolved) Forward4() bool { return r.Sysctl() && r.Shared == nil }

// Forward6 reports whether IPv6 forwarding should be enabled.
func (r *Resolved) Forward6() bool { return r.Sysctl() }

func boolOr(p *bool, def bool) bool {
	if p == nil {
		return def
	}
	return *p
}

// LoadFile reads YAML from path into cfg. A missing file is an error.
func LoadFile(cfg *Config, path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	return LoadYAML(cfg, data)
}

// LoadYAML merges YAML data into cfg. Fields absent from the document keep
// their current value.
func LoadYAML(cfg *Config, data []byte) error {
	dec := yaml.NewDecoder(strings.NewReader(string(data)))
	dec.KnownFields(true)
	if err := dec.Decode(cfg); err != nil {
		if errors.Is(err, os.ErrNotExist) || err.Error() == "EOF" {
			return nil
		}
		return err
	}
	return nil
}

// LoadEnv applies environment overrides. lookup is os.LookupEnv in
// production.
func LoadEnv(cfg *Config, lookup func(string) (string, bool)) error {
	get := func(name string) (string, bool) {
		v, ok := lookup(EnvPrefix + name)
		if !ok {
			return "", false
		}
		return strings.TrimSpace(v), true
	}
	var errs []error
	str := func(name string, dst *string) {
		if v, ok := get(name); ok {
			*dst = v
		}
	}
	integer := func(name string, dst *int) {
		if v, ok := get(name); ok {
			n, err := strconv.Atoi(v)
			if err != nil {
				errs = append(errs, fmt.Errorf("%s%s: %w", EnvPrefix, name, err))
				return
			}
			*dst = n
		}
	}
	boolean := func(name string, dst **bool) {
		if v, ok := get(name); ok {
			b, err := parseBool(v)
			if err != nil {
				errs = append(errs, fmt.Errorf("%s%s: %w", EnvPrefix, name, err))
				return
			}
			*dst = &b
		}
	}
	addr := func(name string, dst *netip.Addr) {
		if v, ok := get(name); ok {
			a, err := netip.ParseAddr(v)
			if err != nil {
				errs = append(errs, fmt.Errorf("%s%s: %w", EnvPrefix, name, err))
				return
			}
			*dst = a
		}
	}
	pfx := func(name string, dst *netip.Prefix) {
		if v, ok := get(name); ok {
			p, err := netip.ParsePrefix(v)
			if err != nil {
				errs = append(errs, fmt.Errorf("%s%s: %w", EnvPrefix, name, err))
				return
			}
			*dst = p
		}
	}
	pfxList := func(name string, dst *[]netip.Prefix) {
		if v, ok := get(name); ok {
			var out []netip.Prefix
			for _, s := range splitList(v) {
				p, err := parseAddrOrPrefix(s)
				if err != nil {
					errs = append(errs, fmt.Errorf("%s%s: %w", EnvPrefix, name, err))
					return
				}
				out = append(out, p)
			}
			*dst = out
		}
	}
	routeList := func(name string, dst *[]Route) {
		if v, ok := get(name); ok {
			var out []Route
			for _, s := range splitList(v) {
				p, err := parseAddrOrPrefix(s)
				if err != nil {
					errs = append(errs, fmt.Errorf("%s%s: %w", EnvPrefix, name, err))
					return
				}
				out = append(out, Route{Prefix: p})
			}
			*dst = out
		}
	}
	clat := func() *CLAT {
		if cfg.CLAT == nil {
			cfg.CLAT = &CLAT{}
		}
		return cfg.CLAT
	}
	strList := func(name string, dst *[]string) {
		if v, ok := get(name); ok {
			*dst = splitList(v)
		}
	}

	if v, ok := get("CONFIG_YAML"); ok && v != "" {
		if err := LoadYAML(cfg, []byte(v)); err != nil {
			return fmt.Errorf("%sCONFIG_YAML: %w", EnvPrefix, err)
		}
	}
	str("INTERFACE", &cfg.Interface.Name)
	integer("MTU", &cfg.Interface.MTU)
	boolean("INTERFACE_CONFIGURE", &cfg.Interface.Configure)
	boolean("INTERFACE_AUTO_ROUTES", &cfg.Interface.AutoRoutes)
	boolean("INTERFACE_SYSCTL", &cfg.Interface.Sysctl)
	pfxList("INTERFACE_ADDRESSES", &cfg.Interface.Addresses)
	routeList("INTERFACE_ROUTES", &cfg.Interface.Routes)
	addr("IPV4_ADDRESS", &cfg.IPv4Address)
	addr("IPV6_ADDRESS", &cfg.IPv6Address)
	pfx("PREFIX", &cfg.Prefix)
	boolean("WKPF_STRICT", &cfg.WKPFStrict)
	if v, ok := get("CLAT"); ok {
		b, err := parseBool(v)
		switch {
		case err != nil:
			errs = append(errs, fmt.Errorf("%sCLAT: %w", EnvPrefix, err))
		case b:
			clat()
		default:
			cfg.CLAT = nil
		}
	}
	if v, ok := get("CLAT_IPV6_ADDRESS"); ok {
		clat().IPv6Address = v
	}
	if v, ok := get("CLAT_IPV4_ADDRESS"); ok {
		a, err := netip.ParseAddr(v)
		if err != nil {
			errs = append(errs, fmt.Errorf("%sCLAT_IPV4_ADDRESS: %w", EnvPrefix, err))
		} else {
			clat().IPv4Address = a
		}
	}
	if v, ok := get("CLAT_PORTS"); ok {
		clat().Ports = splitList(v)
	}
	if v, ok := get("CLAT_TABLE"); ok {
		n, err := strconv.ParseInt(v, 0, 32)
		if err != nil {
			errs = append(errs, fmt.Errorf("%sCLAT_TABLE: %w", EnvPrefix, err))
		} else {
			clat().Table = int(n)
		}
	}
	if v, ok := get("MAPS"); ok {
		cfg.Maps = nil
		for _, s := range splitList(v) {
			sides := strings.SplitN(s, "=", 2)
			if len(sides) != 2 {
				errs = append(errs, fmt.Errorf("%sMAPS: expected ipv4=ipv6, got %q", EnvPrefix, s))
				continue
			}
			cfg.Maps = append(cfg.Maps, Map{IPv4: strings.TrimSpace(sides[0]), IPv6: strings.TrimSpace(sides[1])})
		}
	}
	if v, ok := get("DYNAMIC_POOL"); ok {
		if v == "" {
			cfg.DynamicPool = nil
		} else {
			p, err := netip.ParsePrefix(v)
			if err != nil {
				errs = append(errs, fmt.Errorf("%sDYNAMIC_POOL: %w", EnvPrefix, err))
			} else {
				if cfg.DynamicPool == nil {
					cfg.DynamicPool = &DynamicPool{}
				}
				cfg.DynamicPool.Prefix = p
			}
		}
	}
	if v, ok := get("DYNAMIC_POOL_STATE_FILE"); ok {
		if cfg.DynamicPool == nil {
			cfg.DynamicPool = &DynamicPool{}
		}
		cfg.DynamicPool.StateFile = v
	}
	str("UDP_CHECKSUM", &cfg.UDPChecksum)
	integer("OFFLINK_MTU", &cfg.OfflinkMTU)
	str("LOG_LEVEL", &cfg.Log.Level)
	str("LOG_FORMAT", &cfg.Log.Format)
	strList("LOG_PACKETS", &cfg.Log.Packets)
	str("HTTP_LISTEN", &cfg.HTTP.Listen)
	if v, ok := get("HTTP_ADMIN"); ok {
		b, err := parseBool(v)
		if err != nil {
			errs = append(errs, fmt.Errorf("%sHTTP_ADMIN: %w", EnvPrefix, err))
		} else {
			cfg.HTTP.Admin = b
		}
	}

	// systemd's StateDirectory is honoured like tayga does.
	if sd, ok := lookup("STATE_DIRECTORY"); ok && cfg.DynamicPool != nil && cfg.DynamicPool.StateFile == "" {
		if i := strings.IndexByte(sd, ':'); i >= 0 {
			sd = sd[:i]
		}
		if sd != "" {
			cfg.DynamicPool.StateFile = filepath.Join(sd, "dynamic.map")
		}
	}
	return errors.Join(errs...)
}

func splitList(v string) []string {
	var out []string
	for _, s := range strings.FieldsFunc(v, func(r rune) bool { return r == ',' || r == ' ' || r == '\n' || r == '\t' }) {
		if s != "" {
			out = append(out, s)
		}
	}
	return out
}

func parseBool(v string) (bool, error) {
	switch strings.ToLower(v) {
	case "1", "true", "yes", "on":
		return true, nil
	case "0", "false", "no", "off":
		return false, nil
	}
	return false, fmt.Errorf("invalid boolean %q", v)
}

// parseAddrOrPrefix accepts "a.b.c.d", "a.b.c.d/n" or the IPv6 equivalents.
func parseAddrOrPrefix(s string) (netip.Prefix, error) {
	if strings.Contains(s, "/") {
		return netip.ParsePrefix(s)
	}
	a, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Prefix{}, err
	}
	return netip.PrefixFrom(a, a.BitLen()), nil
}

// ParseUDPChecksum accepts tayga's spellings.
func ParseUDPChecksum(s string) (xlate.UDPChecksumMode, error) {
	switch strings.ToLower(s) {
	case "", "drop":
		return xlate.UDPChecksumDrop, nil
	case "calc", "calculate":
		return xlate.UDPChecksumCalc, nil
	case "fwd", "forward":
		return xlate.UDPChecksumForward, nil
	}
	return 0, fmt.Errorf("udp_checksum: expected drop, calc or forward, got %q", s)
}

// ResolveOptions tunes Resolve.
type ResolveOptions struct {
	// Observer is attached to a newly created dynamic pool.
	Observer xlate.Observer
	// ExistingPool is reused, keeping its assignments, when the configured
	// pool prefix matches its prefix.
	ExistingPool *addrmap.Pool
	// SourceAddr resolves clat.ipv6_address "auto": it returns the source
	// address the kernel uses to reach dst. nil makes "auto" an error.
	SourceAddr func(dst netip.Addr) (netip.Addr, error)
}

// ParseFilter parses a clat.ports entry: "tcp/N-M", "udp/N", "sctp/N-M",
// "icmp", or a bare protocol name for every port.
func ParseFilter(s string) (netconf.Filter, error) {
	proto, ports, hasPorts := strings.Cut(s, "/")
	var f netconf.Filter
	switch strings.ToLower(proto) {
	case "tcp":
		f.Proto = 6
	case "udp":
		f.Proto = 17
	case "sctp":
		f.Proto = 132
	case "icmp", "icmpv6", "ipv6-icmp":
		f.Proto = 58
	default:
		return f, fmt.Errorf("%q: protocol must be tcp, udp, sctp or icmp", s)
	}
	if !hasPorts {
		return f, nil
	}
	if f.Proto == 58 {
		return f, fmt.Errorf("%q: icmp takes no port range", s)
	}
	lo, hi, isRange := strings.Cut(ports, "-")
	if !isRange {
		hi = lo
	}
	port := func(v string) (uint16, error) {
		n, err := strconv.ParseUint(v, 10, 16)
		if err != nil || n == 0 {
			return 0, fmt.Errorf("%q: port must be between 1 and 65535", s)
		}
		return uint16(n), nil
	}
	var err error
	if f.Start, err = port(lo); err != nil {
		return f, err
	}
	if f.End, err = port(hi); err != nil {
		return f, err
	}
	if f.Start > f.End {
		return f, fmt.Errorf("%q: port range is reversed", s)
	}
	return f, nil
}

// Resolve validates cfg and derives everything the daemon needs. obs is
// attached to the dynamic pool for event reporting.
func Resolve(cfg Config, obs xlate.Observer) (*Resolved, error) {
	return ResolveWith(cfg, ResolveOptions{Observer: obs})
}

// ImmutableChanges lists the settings that differ between old and new and
// cannot change without a restart.
func ImmutableChanges(old, new *Resolved) []string {
	var out []string
	if old.Config.Interface.Name != new.Config.Interface.Name {
		out = append(out, "interface.name")
	}
	if old.Config.Interface.MTU != new.Config.Interface.MTU {
		out = append(out, "interface.mtu")
	}
	if old.Configure() != new.Configure() {
		out = append(out, "interface.configure")
	}
	if old.Sysctl() != new.Sysctl() {
		out = append(out, "interface.sysctl")
	}
	if old.HTTPListen != new.HTTPListen {
		out = append(out, "http.listen")
	}
	if old.LogJSON != new.LogJSON {
		out = append(out, "log.format")
	}
	return out
}

// ResolveWith is Resolve with options.
func ResolveWith(cfg Config, ro ResolveOptions) (*Resolved, error) {
	obs := ro.Observer
	r := &Resolved{Config: cfg, PacketKinds: map[xlate.Kind]bool{}}
	var errs []error
	fail := func(format string, a ...any) { errs = append(errs, fmt.Errorf(format, a...)) }
	warn := func(format string, a ...any) { r.Warnings = append(r.Warnings, fmt.Sprintf(format, a...)) }

	// Interface.
	if cfg.Interface.Name == "" {
		r.Config.Interface.Name = DefaultInterface
	}
	if len(r.Config.Interface.Name) > 15 {
		fail("interface.name %q is longer than 15 characters", r.Config.Interface.Name)
	}
	if cfg.Interface.MTU == 0 {
		r.Config.Interface.MTU = DefaultMTU
	}
	if r.Config.Interface.MTU < 1280 || r.Config.Interface.MTU > 65535 {
		fail("interface.mtu %d must be between 1280 and 65535", r.Config.Interface.MTU)
	}
	if cfg.OfflinkMTU == 0 {
		r.Config.OfflinkMTU = DefaultOfflinkMTU
	}
	if r.Config.OfflinkMTU < 1280 {
		fail("offlink_mtu %d must be at least 1280", r.Config.OfflinkMTU)
	}
	udpMode, err := ParseUDPChecksum(cfg.UDPChecksum)
	if err != nil {
		errs = append(errs, err)
	}
	r.Config.UDPChecksum = udpMode.String()

	// Addresses and maps.
	wkpfStrict := boolOr(cfg.WKPFStrict, true)
	b := addrmap.NewBuilder(wkpfStrict)
	if cfg.Prefix.IsValid() {
		if err := b.AddPrefix(cfg.Prefix); err != nil {
			fail("prefix: %v", err)
		}
	}

	// CLAT sharing the host's address.
	var shared6 netip.Addr
	if c := cfg.CLAT; c != nil {
		cc := *c
		r.Config.CLAT = &cc
		if !cfg.IPv4Address.IsValid() {
			cfg.IPv4Address = DefaultCLATTranslatorIPv4
			r.Config.IPv4Address = cfg.IPv4Address
		}
		if !cc.IPv4Address.IsValid() {
			cc.IPv4Address = DefaultCLATHostIPv4
		}
		if !cc.IPv4Address.Is4() {
			fail("clat.ipv4_address %s is not IPv4", cc.IPv4Address)
		} else if cc.IPv4Address == cfg.IPv4Address {
			fail("clat.ipv4_address %s is the translator's own ipv4_address", cc.IPv4Address)
		}
		if cc.Table == 0 {
			cc.Table = DefaultCLATTable
		}
		switch cc.Table {
		case rtTableLocal, rtTableMain, rtTableDefault:
			fail("clat.table %d is a reserved table", cc.Table)
		default:
			if cc.Table < 1 || cc.Table > 0xfffffffe {
				fail("clat.table %d must be between 1 and 4294967294", cc.Table)
			}
		}
		var filters []netconf.Filter
		for _, s := range cc.Ports {
			f, err := ParseFilter(s)
			if err != nil {
				fail("clat.ports: %v", err)
				continue
			}
			filters = append(filters, f)
		}
		switch {
		case !cfg.Prefix.IsValid():
			fail("clat: prefix is required")
		case cc.IPv6Address == "" || strings.EqualFold(cc.IPv6Address, "auto"):
			if ro.SourceAddr == nil {
				fail("clat.ipv6_address: automatic detection is not available here, set the address")
				break
			}
			a, err := ro.SourceAddr(cfg.Prefix.Addr())
			if err != nil {
				fail("clat.ipv6_address: %v", err)
				break
			}
			shared6 = a
			r.Warnings = append(r.Warnings, fmt.Sprintf("clat: sharing the host address %s (source address towards %s)", a, cfg.Prefix))
		default:
			a, err := netip.ParseAddr(cc.IPv6Address)
			if err != nil {
				fail("clat.ipv6_address: %v", err)
			} else {
				shared6 = a
			}
		}
		if shared6.IsValid() {
			switch {
			case !shared6.Is6() || shared6.Is4In6():
				fail("clat.ipv6_address %s is not IPv6", shared6)
			case !netutil.ValidIPv6(shared6.As16()):
				fail("clat.ipv6_address %s is a reserved address", shared6)
			case cfg.Prefix.IsValid() && cfg.Prefix.Contains(shared6):
				fail("clat.ipv6_address %s must not be inside prefix %s", shared6, cfg.Prefix)
			default:
				cc.IPv6Address = shared6.String()
				if err := b.AddStatic(netip.PrefixFrom(cc.IPv4Address, 32), netip.PrefixFrom(shared6, 128)); err != nil {
					fail("clat: %v", err)
				}
			}
		}
		if len(errs) == 0 {
			r.Shared = &netconf.Shared{Addr: shared6, From: cfg.Prefix, Table: cc.Table, Filters: filters}
		}
	}
	for i, m := range cfg.Maps {
		p4, err := parseAddrOrPrefix(m.IPv4)
		if err != nil {
			fail("maps[%d].ipv4: %v", i, err)
			continue
		}
		p6, err := parseAddrOrPrefix(m.IPv6)
		if err != nil {
			fail("maps[%d].ipv6: %v", i, err)
			continue
		}
		if p4.Addr().Is4() && netutil.ClassifyIPv4(p4.Addr().As4()) == netutil.IPv4LinkLocal {
			warn("maps[%d]: using link-local address %s, use with caution", i, p4)
		}
		if err := b.AddStatic(p4, p6); err != nil {
			fail("maps[%d]: %v", i, err)
		}
	}
	if !cfg.Prefix.IsValid() && len(cfg.Maps) == 0 {
		fail("no translation maps or NAT64 prefix configured")
	}

	if !cfg.IPv4Address.IsValid() {
		fail("ipv4_address is required")
	} else if !cfg.IPv4Address.Is4() {
		fail("ipv4_address %s is not IPv4", cfg.IPv4Address)
	} else {
		switch netutil.ClassifyIPv4(cfg.IPv4Address.As4()) {
		case netutil.IPv4Invalid:
			fail("ipv4_address %s is a reserved address", cfg.IPv4Address)
		case netutil.IPv4LinkLocal:
			warn("ipv4_address %s is link-local, use with caution", cfg.IPv4Address)
		}
	}

	local6 := cfg.IPv6Address
	v6Derived := false
	// derived is the address the prefix embeds ipv4_address at; an explicit
	// ipv6_address equal to it (as the effective configuration reports)
	// is treated as derived.
	var derived netip.Addr
	if cfg.Prefix.IsValid() && cfg.IPv4Address.Is4() {
		if a16, err := netutil.Embed(cfg.Prefix.Addr().As16(), cfg.Prefix.Bits(), cfg.IPv4Address.As4()); err == nil {
			derived = netip.AddrFrom16(a16)
		}
	}
	switch {
	case local6.IsValid() && local6 == derived:
		v6Derived = true
	case local6.IsValid():
		if !local6.Is6() || local6.Is4In6() {
			fail("ipv6_address %s is not IPv6", local6)
		} else if !netutil.ValidIPv6(local6.As16()) {
			fail("ipv6_address %s is a reserved address", local6)
		} else if wkpfStrict && netutil.WellKnownPrefix.Contains(local6) {
			fail("ipv6_address must not be inside the well-known prefix 64:ff9b::/96")
		} else if cfg.Prefix.IsValid() && cfg.Prefix.Contains(local6) {
			fail("ipv6_address %s must not be inside prefix %s", local6, cfg.Prefix)
		}
	case !cfg.Prefix.IsValid():
		fail("ipv6_address is required when no prefix is configured")
	case cfg.IPv4Address.Is4():
		a16, err := netutil.Embed(cfg.Prefix.Addr().As16(), cfg.Prefix.Bits(), cfg.IPv4Address.As4())
		if err != nil {
			fail("ipv6_address: cannot derive from prefix: %v", err)
		} else if wkpfStrict && netutil.IsWellKnownPrefix(cfg.Prefix) && netutil.IsPrivateIPv4(cfg.IPv4Address.As4()) {
			fail("ipv6_address must be specified when prefix is 64:ff9b::/96 and ipv4_address is a private address")
		} else if netutil.ClassifyIPv4(cfg.IPv4Address.As4()) != netutil.IPv4Valid {
			fail("ipv6_address must be specified when ipv4_address is link-local")
		} else {
			local6 = netip.AddrFrom16(a16)
			v6Derived = true
		}
	}
	if len(errs) == 0 {
		r.Config.IPv6Address = local6
		if err := b.AddSelf(cfg.IPv4Address, local6, v6Derived); err != nil {
			fail("ipv4_address/ipv6_address: %v", err)
		}
	}

	// Dynamic pool.
	if dp := cfg.DynamicPool; dp != nil {
		if !dp.Prefix.IsValid() {
			fail("dynamic_pool.prefix is required")
		} else {
			var pool *addrmap.Pool
			var err error
			if ro.ExistingPool != nil && ro.ExistingPool.Prefix() == dp.Prefix {
				pool = ro.ExistingPool
				pool.SetLeases(dp.MinLease, dp.MaxLease)
			} else {
				pool, err = addrmap.NewPool(dp.Prefix, addrmap.PoolOptions{MinLease: dp.MinLease, MaxLease: dp.MaxLease, Observer: obs})
			}
			if err != nil {
				fail("dynamic_pool: %v", err)
			} else {
				if netutil.ClassifyIPv4(dp.Prefix.Addr().As4()) == netutil.IPv4LinkLocal {
					warn("dynamic_pool %s is link-local, use with caution", dp.Prefix)
				}
				if dp.StateFile != "" && !filepath.IsAbs(dp.StateFile) {
					fail("dynamic_pool.state_file must be an absolute path")
				}
				r.Pool = pool
				if err := b.SetPool(pool); err != nil {
					fail("dynamic_pool: %v", err)
				}
			}
		}
	}

	if len(errs) > 0 {
		return nil, errors.Join(errs...)
	}
	table, err := b.Build()
	if err != nil {
		return nil, err
	}
	r.Table = table

	r.Xlate = xlate.Config{
		LocalAddr4:  cfg.IPv4Address,
		LocalAddr6:  local6,
		MTU:         r.Config.Interface.MTU,
		OfflinkMTU:  r.Config.OfflinkMTU,
		UDPChecksum: udpMode,
	}

	// Addresses and routes. Explicit routes come first so that they
	// replace an automatic route for the same prefix.
	r.Addresses = append([]netip.Prefix{}, cfg.Interface.Addresses...)
	if r.Shared != nil {
		r.Addresses = append(r.Addresses, netip.PrefixFrom(r.Config.CLAT.IPv4Address, 32))
	}
	r.Addresses = dedupe(r.Addresses)
	var auto []netconf.Route
	if boolOr(cfg.Interface.AutoRoutes, true) {
		for _, e := range table.Entries() {
			switch e.Kind {
			case addrmap.KindStatic:
				if r.Shared != nil && e.V6 == netip.PrefixFrom(shared6, 128) {
					continue // both sides are local addresses
				}
				auto = append(auto, netconf.Route{Prefix: e.V4})
				// The IPv6 side of a static map is a real host the
				// translator sends to, never routed here; only its own
				// address is received through the interface.
				if e.V4 == netip.PrefixFrom(cfg.IPv4Address, 32) && !v6Derived {
					auto = append(auto, netconf.Route{Prefix: e.V6})
				}
			case addrmap.KindRFC6052:
				if r.Shared != nil {
					continue // the PLAT is reached over the network
				}
				auto = append(auto, netconf.Route{Prefix: e.V6})
			case addrmap.KindDynamicPool:
				auto = append(auto, netconf.Route{Prefix: e.V4})
			}
		}
		if r.Shared != nil {
			auto = append(auto, netconf.Route{Prefix: netip.PrefixFrom(netip.IPv4Unspecified(), 0)})
		}
	}
	seen := map[netip.Prefix]bool{}
	for _, rt := range cfg.Interface.Routes {
		nr := rt.netconf()
		if seen[nr.Prefix] {
			continue
		}
		seen[nr.Prefix] = true
		if nr.Prefix.Addr().Is4() {
			r.Routes4 = append(r.Routes4, nr)
		} else {
			r.Routes6 = append(r.Routes6, nr)
		}
	}
	for _, nr := range auto {
		if seen[nr.Prefix] {
			continue
		}
		seen[nr.Prefix] = true
		if nr.Prefix.Addr().Is4() {
			r.Routes4 = append(r.Routes4, nr)
		} else {
			r.Routes6 = append(r.Routes6, nr)
		}
	}

	// Logging and HTTP.
	switch strings.ToLower(cfg.Log.Level) {
	case "", "info":
		r.LogLevel = slog.LevelInfo
	case "debug":
		r.LogLevel = slog.LevelDebug
	case "warn", "warning":
		r.LogLevel = slog.LevelWarn
	case "error":
		r.LogLevel = slog.LevelError
	default:
		return nil, fmt.Errorf("log.level: expected debug, info, warn or error, got %q", cfg.Log.Level)
	}
	switch strings.ToLower(cfg.Log.Format) {
	case "", "json":
		r.LogJSON = true
	case "text":
		r.LogJSON = false
	default:
		return nil, fmt.Errorf("log.format: expected json or text, got %q", cfg.Log.Format)
	}
	for _, k := range cfg.Log.Packets {
		switch strings.ToLower(k) {
		case "drop":
			r.PacketKinds[xlate.KindDrop] = true
		case "reject":
			r.PacketKinds[xlate.KindReject] = true
		case "icmp":
			r.PacketKinds[xlate.KindICMP] = true
		case "self":
			r.PacketKinds[xlate.KindSelf] = true
		case "dyn", "dynamic":
			r.PacketKinds[xlate.KindDynamic] = true
		case "all":
			for i := 0; i < xlate.NumKinds; i++ {
				r.PacketKinds[xlate.Kind(i)] = true
			}
		default:
			return nil, fmt.Errorf("log.packets: unknown kind %q", k)
		}
	}
	switch strings.ToLower(cfg.HTTP.Listen) {
	case "":
		r.HTTPListen = DefaultHTTPListen
	case "off", "none", "disabled":
		r.HTTPListen = ""
	default:
		r.HTTPListen = cfg.HTTP.Listen
	}
	return r, nil
}

func dedupe(ps []netip.Prefix) []netip.Prefix {
	seen := map[netip.Prefix]bool{}
	var out []netip.Prefix
	for _, p := range ps {
		if !seen[p] {
			seen[p] = true
			out = append(out, p)
		}
	}
	return out
}

// Marshal renders cfg as YAML.
func Marshal(cfg Config) ([]byte, error) {
	return yaml.Marshal(cfg)
}
