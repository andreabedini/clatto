package tundev

import (
	"os"
	"sync"

	"golang.zx2c4.com/wireguard/tun"
)

// FakeDevice is an in-memory Device for tests: packets pushed with Inject
// are returned by Read, and packets passed to Write are delivered on Out.
type FakeDevice struct {
	in     chan []byte
	Out    chan []byte
	events chan tun.Event
	once   sync.Once
	closed chan struct{}
	batch  int
	mtu    int
}

// NewFakeDevice creates a fake device with the given batch size.
func NewFakeDevice(batch, mtu int) *FakeDevice {
	return &FakeDevice{
		in:     make(chan []byte, 1024),
		Out:    make(chan []byte, 1024),
		events: make(chan tun.Event),
		closed: make(chan struct{}),
		batch:  batch,
		mtu:    mtu,
	}
}

// Inject queues a packet for the next Read.
func (d *FakeDevice) Inject(pkt []byte) { d.in <- append([]byte(nil), pkt...) }

func (d *FakeDevice) File() *os.File           { return nil }
func (d *FakeDevice) MTU() (int, error)        { return d.mtu, nil }
func (d *FakeDevice) Name() (string, error)    { return "fake0", nil }
func (d *FakeDevice) Events() <-chan tun.Event { return d.events }
func (d *FakeDevice) BatchSize() int           { return d.batch }

func (d *FakeDevice) Close() error {
	d.once.Do(func() { close(d.closed) })
	return nil
}

func (d *FakeDevice) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	var first []byte
	select {
	case <-d.closed:
		return 0, os.ErrClosed
	case first = <-d.in:
	}
	n := 0
	deliver := func(p []byte) {
		sizes[n] = copy(bufs[n][offset:], p)
		n++
	}
	deliver(first)
	for n < len(bufs) {
		select {
		case p := <-d.in:
			deliver(p)
		default:
			return n, nil
		}
	}
	return n, nil
}

func (d *FakeDevice) Write(bufs [][]byte, offset int) (int, error) {
	select {
	case <-d.closed:
		return 0, os.ErrClosed
	default:
	}
	for _, b := range bufs {
		d.Out <- append([]byte(nil), b[offset:]...)
	}
	return len(bufs), nil
}
