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
	UDPChecksum string       `yaml:"udp_checksum,omitempty"`
	OfflinkMTU  int          `yaml:"offlink_mtu,omitempty"`
	Log         Log          `yaml:"log,omitempty"`
	HTTP        HTTP         `yaml:"http,omitempty"`
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
	// ones.
	Routes []netip.Prefix `yaml:"routes,omitempty"`
	// AutoRoutes installs routes for every mapped prefix. Default true.
	AutoRoutes *bool `yaml:"auto_routes,omitempty"`
	// Sysctl enables IPv4 and IPv6 forwarding. Default true.
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
	// Routes4 and Routes6 are the prefixes to route via the interface.
	Routes4 []netip.Prefix
	Routes6 []netip.Prefix
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
	pfxList("INTERFACE_ROUTES", &cfg.Interface.Routes)
	addr("IPV4_ADDRESS", &cfg.IPv4Address)
	addr("IPV6_ADDRESS", &cfg.IPv6Address)
	pfx("PREFIX", &cfg.Prefix)
	boolean("WKPF_STRICT", &cfg.WKPFStrict)
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
	switch {
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

	// Routes.
	if boolOr(cfg.Interface.AutoRoutes, true) {
		for _, e := range table.Entries() {
			switch e.Kind {
			case addrmap.KindStatic:
				r.Routes4 = append(r.Routes4, e.V4)
				if !cfg.Prefix.IsValid() || !cfg.Prefix.Contains(e.V6.Addr()) {
					r.Routes6 = append(r.Routes6, e.V6)
				}
			case addrmap.KindRFC6052:
				r.Routes6 = append(r.Routes6, e.V6)
			case addrmap.KindDynamicPool:
				r.Routes4 = append(r.Routes4, e.V4)
			}
		}
	}
	for _, p := range cfg.Interface.Routes {
		if p.Addr().Is4() {
			r.Routes4 = append(r.Routes4, p.Masked())
		} else {
			r.Routes6 = append(r.Routes6, p.Masked())
		}
	}
	r.Routes4 = dedupe(r.Routes4)
	r.Routes6 = dedupe(r.Routes6)

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
