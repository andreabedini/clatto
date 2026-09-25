// Package tundev moves packets between a tun device and the translator.
package tundev

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"sync/atomic"
	"time"

	"golang.zx2c4.com/wireguard/tun"

	"github.com/andreabedini/clatto/internal/xlate"
)

// Offset is the headroom kept in front of every packet buffer for the
// virtio-net header that wireguard-go's tun implementation prepends.
const Offset = 16

// maxPacket is the largest IP packet.
const maxPacket = 65535

// Device is the tun abstraction used by the engine.
type Device = tun.Device

// Create opens a tun interface with the given name and MTU.
func Create(name string, mtu int) (Device, error) {
	return tun.CreateTUN(name, mtu)
}

// Stats counts what the engine has done.
type Stats struct {
	PacketsIn   uint64
	PacketsOut  uint64
	BytesIn     uint64
	BytesOut    uint64
	ReadErrors  uint64
	WriteErrors uint64
}

// Engine reads packets from a device in batches, translates them and writes
// the results back. The translator can be swapped at any time.
type Engine struct {
	dev Device
	tr  atomic.Pointer[xlate.Translator]
	log *slog.Logger

	packetsIn, packetsOut, bytesIn, bytesOut, readErrors, writeErrors atomic.Uint64
}

// NewEngine creates an engine for dev.
func NewEngine(dev Device, tr *xlate.Translator, log *slog.Logger) *Engine {
	e := &Engine{dev: dev, log: log}
	e.tr.Store(tr)
	return e
}

// SetTranslator swaps the translator used for subsequent packets.
func (e *Engine) SetTranslator(tr *xlate.Translator) { e.tr.Store(tr) }

// Translator returns the current translator.
func (e *Engine) Translator() *xlate.Translator { return e.tr.Load() }

// Stats returns a snapshot of the counters.
func (e *Engine) Stats() Stats {
	return Stats{
		PacketsIn:   e.packetsIn.Load(),
		PacketsOut:  e.packetsOut.Load(),
		BytesIn:     e.bytesIn.Load(),
		BytesOut:    e.bytesOut.Load(),
		ReadErrors:  e.readErrors.Load(),
		WriteErrors: e.writeErrors.Load(),
	}
}

// emitter hands out output buffers from a free list and remembers them for
// the next write. It is used by a single goroutine.
type emitter struct {
	out  [][]byte
	free [][]byte
}

func (m *emitter) Packet(n int) []byte {
	if n > maxPacket {
		return nil
	}
	var buf []byte
	if k := len(m.free); k > 0 {
		buf = m.free[k-1]
		m.free = m.free[:k-1]
	} else {
		buf = make([]byte, Offset+maxPacket)
	}
	buf = buf[:Offset+n]
	m.out = append(m.out, buf)
	return buf[Offset:]
}

func (m *emitter) recycle() {
	for _, b := range m.out {
		m.free = append(m.free, b[:cap(b)])
	}
	m.out = m.out[:0]
}

// Run processes packets until ctx is cancelled or the device fails. The
// device is closed when Run returns.
func (e *Engine) Run(ctx context.Context) error {
	batch := e.dev.BatchSize()
	if batch < 1 {
		batch = 1
	}
	bufs := make([][]byte, batch)
	for i := range bufs {
		bufs[i] = make([]byte, Offset+maxPacket)
	}
	sizes := make([]int, batch)
	em := &emitter{}

	closed := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			e.dev.Close()
		case <-closed:
		}
	}()
	defer close(closed)
	defer e.dev.Close()

	consecutiveErrors := 0
	for {
		n, err := e.dev.Read(bufs, sizes, Offset)
		if err != nil {
			if errors.Is(err, os.ErrClosed) || ctx.Err() != nil {
				return ctx.Err()
			}
			e.readErrors.Add(1)
			consecutiveErrors++
			e.log.Warn("tun read failed", "error", err)
			if consecutiveErrors > 10 {
				return err
			}
			time.Sleep(10 * time.Millisecond)
			continue
		}
		consecutiveErrors = 0
		tr := e.tr.Load()
		for i := 0; i < n; i++ {
			pkt := bufs[i][Offset : Offset+sizes[i]]
			e.packetsIn.Add(1)
			e.bytesIn.Add(uint64(len(pkt)))
			tr.Translate(pkt, em)
		}
		if len(em.out) == 0 {
			continue
		}
		var outBytes uint64
		for _, b := range em.out {
			outBytes += uint64(len(b) - Offset)
		}
		if _, err := e.dev.Write(em.out, Offset); err != nil {
			if errors.Is(err, os.ErrClosed) {
				em.recycle()
				return ctx.Err()
			}
			e.writeErrors.Add(1)
			e.log.Warn("tun write failed", "error", err, "packets", len(em.out))
		} else {
			e.packetsOut.Add(uint64(len(em.out)))
			e.bytesOut.Add(outBytes)
		}
		em.recycle()
	}
}
