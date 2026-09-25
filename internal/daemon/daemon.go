// Package daemon ties the tun engine, the kernel configuration and the
// observers together and applies configuration changes at runtime.
package daemon

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/andreabedini/clatto/internal/addrmap"
	"github.com/andreabedini/clatto/internal/config"
	"github.com/andreabedini/clatto/internal/netconf"
	"github.com/andreabedini/clatto/internal/observe"
	"github.com/andreabedini/clatto/internal/tundev"
	"github.com/andreabedini/clatto/internal/xlate"
)

// ErrInvalid wraps configuration errors, as opposed to failures applying a
// valid configuration.
var ErrInvalid = errors.New("invalid configuration")

// Options configures a Daemon.
type Options struct {
	Log      *slog.Logger
	Level    *slog.LevelVar
	Registry *prometheus.Registry
	// LoadFile returns the configuration from the file and the environment.
	// It is used by Reload; nil disables file reloads.
	LoadFile func() (config.Config, error)
	// NewDevice creates the tun device; defaults to tundev.Create.
	NewDevice func(name string, mtu int) (tundev.Device, error)
	// MaintainInterval is how often the dynamic pool is aged and saved.
	MaintainInterval time.Duration
	// SourceAddr resolves clat.ipv6_address "auto" on reload; defaults to
	// netconf.SourceAddress.
	SourceAddr func(dst netip.Addr) (netip.Addr, error)
}

// Status describes the configuration state.
type Status struct {
	Generation  int       `json:"generation"`
	Source      string    `json:"source"`
	AppliedAt   time.Time `json:"applied_at"`
	LastError   string    `json:"last_error,omitempty"`
	LastErrorAt time.Time `json:"last_error_at,omitempty"`
	Interface   string    `json:"interface"`
	Ready       bool      `json:"ready"`
}

// Daemon is the running translator.
type Daemon struct {
	o         Options
	log       *slog.Logger
	metrics   *observe.Metrics
	cfgMet    *observe.ConfigMetrics
	packetLog *observe.PacketLogger
	obs       xlate.Observer

	mu      sync.Mutex
	cur     *config.Resolved
	dev     tundev.Device
	eng     *tundev.Engine
	applied netconf.Options
	started bool
	status  Status
	ready   atomic.Bool
}

// New creates a daemon for an initial resolved configuration. The dynamic
// pool state file, if any, is loaded here.
func New(initial *config.Resolved, o Options) *Daemon {
	if o.Log == nil {
		o.Log = slog.Default()
	}
	if o.Level == nil {
		o.Level = new(slog.LevelVar)
	}
	if o.Registry == nil {
		o.Registry = prometheus.NewRegistry()
	}
	if o.NewDevice == nil {
		o.NewDevice = tundev.Create
	}
	if o.MaintainInterval <= 0 {
		o.MaintainInterval = 45 * time.Second
	}
	if o.SourceAddr == nil {
		o.SourceAddr = netconf.SourceAddress
	}
	d := &Daemon{o: o, log: o.Log, cur: initial}
	d.metrics = observe.NewMetrics(o.Registry)
	d.cfgMet = observe.NewConfigMetrics(o.Registry)
	d.packetLog = observe.NewPacketLogger(o.Log, initial.PacketKinds)
	d.obs = xlate.MultiObserver{d.metrics, d.packetLog}
	observe.RegisterPool(o.Registry, d.Pool)
	o.Level.Set(initial.LogLevel)
	if initial.Pool != nil {
		initial.Pool.SetObserver(d.obs)
		d.loadPoolState(initial)
	}
	d.status = Status{Generation: 1, Source: "startup", AppliedAt: time.Now(), Interface: initial.Config.Interface.Name}
	d.cfgMet.Generation.Set(1)
	d.cfgMet.LastReload.SetToCurrentTime()
	return d
}

func (d *Daemon) loadPoolState(r *config.Resolved) {
	sf := r.Config.DynamicPool.StateFile
	if sf == "" {
		return
	}
	n, err := r.Pool.Load(sf)
	if err != nil {
		d.log.Error("load dynamic pool state", "path", sf, "error", err)
		return
	}
	d.log.Info("loaded dynamic pool state", "path", sf, "entries", n)
}

func (d *Daemon) savePoolState(r *config.Resolved, force bool) {
	if r == nil || r.Pool == nil || r.Config.DynamicPool == nil || r.Config.DynamicPool.StateFile == "" {
		return
	}
	if !force && !r.Pool.Dirty() {
		return
	}
	sf := r.Config.DynamicPool.StateFile
	if err := r.Pool.Save(sf); err != nil {
		d.log.Error("save dynamic pool state", "path", sf, "error", err)
	}
}

// Pool returns the current dynamic pool, or nil.
func (d *Daemon) Pool() *addrmap.Pool {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.cur == nil {
		return nil
	}
	return d.cur.Pool
}

// Ready reports whether packets are being translated.
func (d *Daemon) Ready() bool { return d.ready.Load() }

// Status returns the configuration state.
func (d *Daemon) Status() Status {
	d.mu.Lock()
	defer d.mu.Unlock()
	s := d.status
	s.Ready = d.ready.Load()
	return s
}

// ConfigYAML renders the effective configuration.
func (d *Daemon) ConfigYAML() ([]byte, error) {
	d.mu.Lock()
	cfg := d.cur.Config
	d.mu.Unlock()
	return config.Marshal(cfg)
}

// Engine returns the packet engine once started.
func (d *Daemon) Engine() *tundev.Engine {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.eng
}

// Run creates the device, configures the kernel and translates packets
// until ctx is cancelled or the engine fails.
func (d *Daemon) Run(ctx context.Context) error {
	d.mu.Lock()
	r := d.cur
	dev, err := d.o.NewDevice(r.Config.Interface.Name, r.Config.Interface.MTU)
	if err != nil {
		d.mu.Unlock()
		return fmt.Errorf("create tun device %s: %w (the process needs CAP_NET_ADMIN and /dev/net/tun)", r.Config.Interface.Name, err)
	}
	name, _ := dev.Name()
	d.log.Info("tun device created", "name", name, "mtu", r.Config.Interface.MTU, "batch", dev.BatchSize())
	want := d.netconfOptions(r, name)
	if r.Configure() {
		if err := netconf.Apply(want, d.log); err != nil {
			dev.Close()
			d.mu.Unlock()
			return fmt.Errorf("configure interface: %w", err)
		}
	} else {
		d.log.Info("interface configuration disabled; bring the link up and add routes yourself")
	}
	d.applied = want
	d.dev = dev
	d.eng = tundev.NewEngine(dev, xlate.New(r.Xlate, r.Table, d.obs), d.log)
	observe.RegisterEngine(d.o.Registry, d.eng)
	d.started = true
	d.mu.Unlock()

	engineErr := make(chan error, 1)
	go func() { engineErr <- d.eng.Run(ctx) }()
	d.ready.Store(true)
	d.log.Info("translating")

	t := time.NewTicker(d.o.MaintainInterval)
	defer t.Stop()
	var runErr error
loop:
	for {
		select {
		case <-ctx.Done():
			break loop
		case err := <-engineErr:
			runErr = err
			break loop
		case <-t.C:
			d.mu.Lock()
			r := d.cur
			d.mu.Unlock()
			if r.Pool != nil {
				r.Pool.Maintain()
				d.savePoolState(r, false)
			}
		}
	}
	d.ready.Store(false)
	if runErr == nil {
		runErr = <-engineErr
	}
	d.mu.Lock()
	d.savePoolState(d.cur, true)
	d.mu.Unlock()
	if errors.Is(runErr, context.Canceled) {
		return nil
	}
	return runErr
}

func (d *Daemon) netconfOptions(r *config.Resolved, name string) netconf.Options {
	return netconf.Options{
		Name:      name,
		Addresses: r.Addresses,
		Routes4:   r.Routes4,
		Routes6:   r.Routes6,
		Forward4:  r.Forward4(),
		Forward6:  r.Forward6(),
		Shared:    r.Shared,
	}
}

// ApplyYAML parses a complete configuration document and applies it.
func (d *Daemon) ApplyYAML(data []byte, source string) error {
	var cfg config.Config
	if err := config.LoadYAML(&cfg, data); err != nil {
		return d.fail(source, fmt.Errorf("%w: %v", ErrInvalid, err))
	}
	return d.Apply(cfg, source)
}

// Reload re-reads the configuration file and environment.
func (d *Daemon) Reload(source string) error {
	if d.o.LoadFile == nil {
		return d.fail(source, fmt.Errorf("%w: no configuration file to reload", ErrInvalid))
	}
	cfg, err := d.o.LoadFile()
	if err != nil {
		return d.fail(source, fmt.Errorf("%w: %v", ErrInvalid, err))
	}
	return d.Apply(cfg, source)
}

// Apply validates cfg and switches to it atomically. On error the running
// configuration is unchanged, except that a failure while updating routes
// may leave the kernel partially updated; the error says so.
func (d *Daemon) Apply(cfg config.Config, source string) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	r, err := config.ResolveWith(cfg, config.ResolveOptions{Observer: d.obs, ExistingPool: d.cur.Pool, SourceAddr: d.o.SourceAddr})
	if err != nil {
		return d.failLocked(source, fmt.Errorf("%w: %v", ErrInvalid, err))
	}
	if changed := config.ImmutableChanges(d.cur, r); len(changed) > 0 {
		return d.failLocked(source, fmt.Errorf("%w: %v cannot change without a restart", ErrInvalid, changed))
	}

	if r.Pool != nil && r.Pool != d.cur.Pool {
		r.Pool.SetObserver(d.obs)
		d.savePoolState(d.cur, true)
		d.loadPoolState(r)
	}

	if d.started && r.Configure() {
		want := d.netconfOptions(r, d.applied.Name)
		if err := netconf.Update(d.applied, want, d.log); err != nil {
			return d.failLocked(source, fmt.Errorf("update interface (kernel state may be partially updated): %w", err))
		}
		d.applied = want
	}
	if d.eng != nil {
		d.eng.SetTranslator(xlate.New(r.Xlate, r.Table, d.obs))
	}
	d.o.Level.Set(r.LogLevel)
	d.packetLog.SetKinds(r.PacketKinds)
	d.cur = r

	d.status.Generation++
	d.status.Source = source
	d.status.AppliedAt = time.Now()
	d.status.LastError = ""
	d.cfgMet.Generation.Set(float64(d.status.Generation))
	d.cfgMet.LastReload.SetToCurrentTime()
	d.cfgMet.Reloads.WithLabelValues(source, "ok").Inc()
	d.log.Info("configuration applied", "generation", d.status.Generation, "source", source)
	for _, w := range r.Warnings {
		d.log.Warn(w)
	}
	for _, e := range r.Table.Entries() {
		d.log.Info("mapping", "entry", e.String())
	}
	return nil
}

func (d *Daemon) fail(source string, err error) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.failLocked(source, err)
}

func (d *Daemon) failLocked(source string, err error) error {
	d.status.LastError = err.Error()
	d.status.LastErrorAt = time.Now()
	d.cfgMet.Reloads.WithLabelValues(source, "error").Inc()
	d.log.Error("configuration rejected", "source", source, "error", err)
	return err
}

// WatchFile polls path and reloads when its contents change, until ctx is
// done. It is meant for ConfigMap volumes, which update atomically.
func (d *Daemon) WatchFile(ctx context.Context, path string, interval time.Duration) {
	last := fileHash(path)
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			h := fileHash(path)
			if h == last || h == "" {
				continue
			}
			last = h
			d.log.Info("configuration file changed", "path", path)
			d.Reload("file")
		}
	}
}

func fileHash(path string) string {
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return fmt.Sprintf("%x", sha256.Sum256(data))
}
