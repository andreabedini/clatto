// Package observe implements the translator's observers: Prometheus metrics
// and packet event logging.
package observe

import (
	"log/slog"
	"strconv"
	"sync/atomic"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/andreabedini/clatto/internal/addrmap"
	"github.com/andreabedini/clatto/internal/tundev"
	"github.com/andreabedini/clatto/internal/xlate"
)

// Metrics is an xlate.Observer that counts into Prometheus metrics. All
// counters are pre-resolved so the packet path does no label lookups.
type Metrics struct {
	packets [2]prometheus.Counter // index 0: 4to6, 1: 6to4
	bytes   [2]prometheus.Counter
	events  [2][xlate.NumKinds][xlate.NumReasons]prometheus.Counter
}

// NewMetrics registers the translation metrics with reg.
func NewMetrics(reg prometheus.Registerer) *Metrics {
	m := &Metrics{}
	packets := prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "clatto_translated_packets_total",
		Help: "Packets successfully translated, by direction.",
	}, []string{"direction"})
	bytes := prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "clatto_translated_bytes_total",
		Help: "Bytes of input packets successfully translated, by direction.",
	}, []string{"direction"})
	events := prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "clatto_packet_events_total",
		Help: "Packets dropped, rejected, answered with ICMP or addressed to the translator, by input family, kind and reason.",
	}, []string{"family", "kind", "reason"})
	reg.MustRegister(packets, bytes, events)
	for i, dir := range []string{"4to6", "6to4"} {
		m.packets[i] = packets.WithLabelValues(dir)
		m.bytes[i] = bytes.WithLabelValues(dir)
	}
	for f, family := range []string{"4", "6"} {
		for k := 0; k < xlate.NumKinds; k++ {
			for r := 0; r < xlate.NumReasons; r++ {
				m.events[f][k][r] = events.WithLabelValues(family, xlate.Kind(k).String(), xlate.Reason(r).String())
			}
		}
	}
	return m
}

func familyIndex(f uint8) int {
	if f == 6 {
		return 1
	}
	return 0
}

// Translated implements xlate.Observer.
func (m *Metrics) Translated(family uint8, n int) {
	i := familyIndex(family)
	m.packets[i].Inc()
	m.bytes[i].Add(float64(n))
}

// Event implements xlate.Observer.
func (m *Metrics) Event(e xlate.Event) {
	if int(e.Kind) >= xlate.NumKinds || int(e.Reason) >= xlate.NumReasons {
		return
	}
	m.events[familyIndex(e.Family)][e.Kind][e.Reason].Inc()
}

// RegisterPool exposes dynamic pool occupancy. pool returns the current
// pool, or nil when none is configured.
func RegisterPool(reg prometheus.Registerer, pool func() *addrmap.Pool) {
	stat := func(get func(addrmap.Stats) int) func() float64 {
		return func() float64 {
			p := pool()
			if p == nil {
				return 0
			}
			return float64(get(p.Stats()))
		}
	}
	reg.MustRegister(
		prometheus.NewGaugeFunc(prometheus.GaugeOpts{Name: "clatto_dynamic_pool_size", Help: "Addresses available in the dynamic pool."},
			stat(func(s addrmap.Stats) int { return s.Size })),
		prometheus.NewGaugeFunc(prometheus.GaugeOpts{Name: "clatto_dynamic_pool_mapped", Help: "Dynamic assignments currently active."},
			stat(func(s addrmap.Stats) int { return s.Mapped })),
		prometheus.NewGaugeFunc(prometheus.GaugeOpts{Name: "clatto_dynamic_pool_dormant", Help: "Dynamic assignments idle but still reserved."},
			stat(func(s addrmap.Stats) int { return s.Dormant })),
	)
}

// ConfigMetrics tracks configuration reloads.
type ConfigMetrics struct {
	Generation prometheus.Gauge
	LastReload prometheus.Gauge
	Reloads    *prometheus.CounterVec
}

// NewConfigMetrics registers reload metrics.
func NewConfigMetrics(reg prometheus.Registerer) *ConfigMetrics {
	m := &ConfigMetrics{
		Generation: prometheus.NewGauge(prometheus.GaugeOpts{Name: "clatto_config_generation", Help: "Number of the configuration currently applied; increments on every successful reload."}),
		LastReload: prometheus.NewGauge(prometheus.GaugeOpts{Name: "clatto_config_last_success_timestamp_seconds", Help: "Unix time of the last successfully applied configuration."}),
		Reloads:    prometheus.NewCounterVec(prometheus.CounterOpts{Name: "clatto_config_reloads_total", Help: "Configuration reload attempts by source and result."}, []string{"source", "result"}),
	}
	reg.MustRegister(m.Generation, m.LastReload, m.Reloads)
	return m
}

// RegisterEngine exposes tun device counters.
func RegisterEngine(reg prometheus.Registerer, eng *tundev.Engine) {
	counter := func(name, help string, get func(tundev.Stats) uint64) prometheus.Collector {
		return prometheus.NewCounterFunc(prometheus.CounterOpts{Name: name, Help: help}, func() float64 { return float64(get(eng.Stats())) })
	}
	reg.MustRegister(
		counter("clatto_tun_packets_received_total", "Packets read from the tun device.", func(s tundev.Stats) uint64 { return s.PacketsIn }),
		counter("clatto_tun_packets_sent_total", "Packets written to the tun device.", func(s tundev.Stats) uint64 { return s.PacketsOut }),
		counter("clatto_tun_bytes_received_total", "Bytes read from the tun device.", func(s tundev.Stats) uint64 { return s.BytesIn }),
		counter("clatto_tun_bytes_sent_total", "Bytes written to the tun device.", func(s tundev.Stats) uint64 { return s.BytesOut }),
		counter("clatto_tun_read_errors_total", "Failed reads from the tun device.", func(s tundev.Stats) uint64 { return s.ReadErrors }),
		counter("clatto_tun_write_errors_total", "Failed writes to the tun device.", func(s tundev.Stats) uint64 { return s.WriteErrors }),
	)
}

// RegisterBuildInfo exposes the version as a gauge.
func RegisterBuildInfo(reg prometheus.Registerer, version string) {
	g := prometheus.NewGaugeVec(prometheus.GaugeOpts{Name: "clatto_build_info", Help: "Build information."}, []string{"version"})
	g.WithLabelValues(version).Set(1)
	reg.MustRegister(g)
}

// PacketLogger logs packet events of selected kinds.
type PacketLogger struct {
	log   *slog.Logger
	kinds atomic.Pointer[[xlate.NumKinds]bool]
}

// NewPacketLogger logs events whose kind is enabled in kinds.
func NewPacketLogger(log *slog.Logger, kinds map[xlate.Kind]bool) *PacketLogger {
	pl := &PacketLogger{log: log}
	pl.SetKinds(kinds)
	return pl
}

// SetKinds replaces the set of logged kinds.
func (pl *PacketLogger) SetKinds(kinds map[xlate.Kind]bool) {
	var arr [xlate.NumKinds]bool
	for k, on := range kinds {
		if int(k) < xlate.NumKinds {
			arr[k] = on
		}
	}
	pl.kinds.Store(&arr)
}

// Translated implements xlate.Observer.
func (*PacketLogger) Translated(uint8, int) {}

// Event implements xlate.Observer.
func (pl *PacketLogger) Event(e xlate.Event) {
	if int(e.Kind) >= xlate.NumKinds || !pl.kinds.Load()[e.Kind] {
		return
	}
	if e.Kind == xlate.KindDynamic {
		pl.log.Info("dynamic pool", "event", e.Reason.String(), "ipv4", e.Src, "ipv6", e.Dst)
		return
	}
	pl.log.Info("packet "+e.Kind.String(),
		"reason", e.Reason.String(),
		"family", strconv.Itoa(int(e.Family)),
		"src", e.Src, "dst", e.Dst,
		"proto", e.Proto, "len", e.Length)
}
