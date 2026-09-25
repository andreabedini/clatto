// Command bench pushes UDP or TCP traffic through a NAT64 translator and
// reports what came out the other side and what it cost the translator.
//
// The topology is the one test/bench.sh sets up: an IPv6 client address
// and an IPv4 server address on lo, and a translator whose tun device
// carries 64:ff9b::/96 towards IPv4 and the client's mapped IPv4 address
// back. Traffic from the client to the server's NAT64 address crosses the
// translator once per direction.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Result is one measurement.
type Result struct {
	Translator string  `json:"translator"`
	Proto      string  `json:"proto"`
	Size       int     `json:"size"`
	Flows      int     `json:"flows"`
	Seconds    float64 `json:"seconds"`
	Sent       int64   `json:"sent_packets"`
	Received   int64   `json:"received_packets,omitempty"`
	Bytes      int64   `json:"received_bytes"`
	PPS        float64 `json:"received_pps,omitempty"`
	Mbps       float64 `json:"mbps"`
	Loss       float64 `json:"loss_percent,omitempty"`
	CPUSeconds float64 `json:"translator_cpu_seconds"`
	// CPUPerPacket is translator CPU time per received packet (UDP,
	// one direction) in microseconds.
	CPUPerPacket float64 `json:"translator_cpu_us_per_packet,omitempty"`
	// CPUPerMB is translator CPU time per megabyte of goodput in
	// milliseconds (TCP, where the acknowledgements cross it too).
	CPUPerMB float64 `json:"translator_cpu_ms_per_mb,omitempty"`
}

func main() {
	var (
		name     = flag.String("translator", "", "name of the translator under test, for the report")
		proto    = flag.String("proto", "udp", "udp or tcp")
		size     = flag.Int("size", 1400, "UDP payload size in bytes")
		flows    = flag.Int("flows", 1, "concurrent senders")
		duration = flag.Duration("duration", 5*time.Second, "how long to send")
		pid      = flag.Int("pid", 0, "translator process to account CPU time to")
		client   = flag.String("client", "2001:db8::1", "IPv6 source address")
		server   = flag.String("server", "10.0.0.1", "IPv4 server address")
		target   = flag.String("target", "64:ff9b::10.0.0.1", "the server's NAT64 address")
		port     = flag.Int("port", 5555, "server port")
		asJSON   = flag.Bool("json", false, "print the result as JSON")
	)
	flag.Parse()
	var r Result
	var err error
	switch *proto {
	case "udp":
		r, err = runUDP(*client, *server, *target, *port, *size, *flows, *duration, *pid)
	case "tcp":
		r, err = runTCP(*client, *server, *target, *port, *flows, *duration, *pid)
	default:
		err = fmt.Errorf("unknown proto %q", *proto)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "bench:", err)
		os.Exit(1)
	}
	r.Translator = *name
	if *asJSON {
		json.NewEncoder(os.Stdout).Encode(r)
		return
	}
	switch r.Proto {
	case "udp":
		fmt.Printf("%-7s udp size=%-5d flows=%d  %9.0f pps  %8.1f Mbit/s  loss %5.1f%%  cpu %5.2fs  %6.2f us/pkt\n",
			r.Translator, r.Size, r.Flows, r.PPS, r.Mbps, r.Loss, r.CPUSeconds, r.CPUPerPacket)
	case "tcp":
		fmt.Printf("%-7s tcp            flows=%d  %8.1f Mbit/s  cpu %5.2fs  %6.2f ms/MB\n",
			r.Translator, r.Flows, r.Mbps, r.CPUSeconds, r.CPUPerMB)
	}
}

// cpuSeconds returns the CPU time the process has consumed, summed over
// its threads from /proc/<pid>/task/*/schedstat (the process's own
// schedstat covers the main thread only), or 0 when pid is 0.
func cpuSeconds(pid int) (float64, error) {
	if pid == 0 {
		return 0, nil
	}
	tasks, err := os.ReadDir(fmt.Sprintf("/proc/%d/task", pid))
	if err != nil {
		return 0, err
	}
	var total float64
	for _, t := range tasks {
		data, err := os.ReadFile(fmt.Sprintf("/proc/%d/task/%s/schedstat", pid, t.Name()))
		if err != nil {
			continue // the thread exited meanwhile
		}
		fields := strings.Fields(string(data))
		if len(fields) < 1 {
			return 0, fmt.Errorf("unexpected schedstat %q", data)
		}
		ns, err := strconv.ParseFloat(fields[0], 64)
		if err != nil {
			return 0, err
		}
		total += ns
	}
	return total / 1e9, nil
}

func runUDP(client, server, target string, port, size, flows int, d time.Duration, pid int) (Result, error) {
	srv, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP(server), Port: port})
	if err != nil {
		return Result{}, fmt.Errorf("listen: %w", err)
	}
	defer srv.Close()
	srv.SetReadBuffer(8 << 20)
	var received, bytes int64
	go func() {
		buf := make([]byte, 65536)
		for {
			n, _, err := srv.ReadFromUDP(buf)
			if err != nil {
				return
			}
			atomic.AddInt64(&received, 1)
			atomic.AddInt64(&bytes, int64(n))
		}
	}()

	cpu0, err := cpuSeconds(pid)
	if err != nil {
		return Result{}, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), d)
	defer cancel()
	var sent int64
	var wg sync.WaitGroup
	start := time.Now()
	for i := 0; i < flows; i++ {
		conn, err := net.DialUDP("udp6", &net.UDPAddr{IP: net.ParseIP(client)}, &net.UDPAddr{IP: net.ParseIP(target), Port: port})
		if err != nil {
			return Result{}, fmt.Errorf("dial: %w", err)
		}
		defer conn.Close()
		conn.SetWriteBuffer(8 << 20)
		wg.Add(1)
		go func() {
			defer wg.Done()
			msg := make([]byte, size)
			var n int64
			for ctx.Err() == nil {
				if _, err := conn.Write(msg); err == nil {
					n++
				}
			}
			atomic.AddInt64(&sent, n)
		}()
	}
	wg.Wait()
	// Let what is queued in the tun drain before counting.
	time.Sleep(200 * time.Millisecond)
	elapsed := time.Since(start).Seconds()
	cpu1, err := cpuSeconds(pid)
	if err != nil {
		return Result{}, err
	}
	r := Result{Proto: "udp", Size: size, Flows: flows, Seconds: elapsed, Sent: sent,
		Received: atomic.LoadInt64(&received), Bytes: atomic.LoadInt64(&bytes), CPUSeconds: cpu1 - cpu0}
	r.PPS = float64(r.Received) / elapsed
	r.Mbps = float64(r.Bytes) * 8 / elapsed / 1e6
	if sent > 0 {
		r.Loss = 100 * float64(sent-r.Received) / float64(sent)
	}
	if r.Received > 0 {
		r.CPUPerPacket = r.CPUSeconds / float64(r.Received) * 1e6
	}
	return r, nil
}

func runTCP(client, server, target string, port, flows int, d time.Duration, pid int) (Result, error) {
	ln, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.ParseIP(server), Port: port})
	if err != nil {
		return Result{}, fmt.Errorf("listen: %w", err)
	}
	defer ln.Close()
	var bytes int64
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				buf := make([]byte, 256<<10)
				for {
					n, err := c.Read(buf)
					atomic.AddInt64(&bytes, int64(n))
					if err != nil {
						return
					}
				}
			}()
		}
	}()

	cpu0, err := cpuSeconds(pid)
	if err != nil {
		return Result{}, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), d)
	defer cancel()
	var wg sync.WaitGroup
	start := time.Now()
	dialer := net.Dialer{LocalAddr: &net.TCPAddr{IP: net.ParseIP(client)}, Timeout: 5 * time.Second}
	for i := 0; i < flows; i++ {
		conn, err := dialer.Dial("tcp6", net.JoinHostPort(target, strconv.Itoa(port)))
		if err != nil {
			return Result{}, fmt.Errorf("dial: %w", err)
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer conn.Close()
			buf := make([]byte, 256<<10)
			for ctx.Err() == nil {
				conn.SetWriteDeadline(time.Now().Add(time.Second))
				if _, err := conn.Write(buf); err != nil && ctx.Err() == nil {
					if ne, ok := err.(net.Error); ok && ne.Timeout() {
						continue
					}
					fmt.Fprintln(os.Stderr, "write:", err)
					return
				}
			}
		}()
	}
	wg.Wait()
	elapsed := time.Since(start).Seconds()
	cpu1, err := cpuSeconds(pid)
	if err != nil {
		return Result{}, err
	}
	r := Result{Proto: "tcp", Flows: flows, Seconds: elapsed, Bytes: atomic.LoadInt64(&bytes), CPUSeconds: cpu1 - cpu0}
	r.Mbps = float64(r.Bytes) * 8 / elapsed / 1e6
	if r.Bytes > 0 {
		r.CPUPerMB = r.CPUSeconds / (float64(r.Bytes) / 1e6) * 1e3
	}
	return r, nil
}
