package daemon

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/andreabedini/clatto/internal/observe"
	"github.com/andreabedini/clatto/internal/xlate"
)

// benchEmitter recycles one output buffer, like the engine's emitter.
type benchEmitter struct{ buf []byte }

func (b *benchEmitter) Packet(n int) []byte {
	if cap(b.buf) < n {
		b.buf = make([]byte, n)
	}
	return b.buf[:n]
}

// BenchmarkTranslate measures the translator alone, with the observers
// the daemon attaches, on a 1400-byte IPv6 UDP packet bound for the prefix.
func BenchmarkTranslate(b *testing.B) {
	r := resolve(&testing.T{}, baseYAML)
	reg := prometheus.NewRegistry()
	obs := xlate.MultiObserver{observe.NewMetrics(reg), observe.NewPacketLogger(nil, nil)}
	tr := xlate.New(r.Xlate, r.Table, obs)
	pkt := udp6("2001:db8::10", "64:ff9b::8.8.8.8")
	payload := make([]byte, len(pkt)+1400)
	copy(payload, pkt)
	// Fix up the IPv6 payload length and the UDP length for the padding.
	plen := len(payload) - 40
	payload[4], payload[5] = byte(plen>>8), byte(plen)
	payload[44], payload[45] = byte(plen>>8), byte(plen)
	em := &benchEmitter{}
	in := make([]byte, len(payload))
	b.SetBytes(int64(len(payload)))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		copy(in, payload) // the translator may modify its input
		tr.Translate(in, em)
	}
}
