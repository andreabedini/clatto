// Command clatto is a stateless NAT64 / CLAT translator built to run as a
// Kubernetes sidecar.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"

	"github.com/andreabedini/clatto/internal/admin"
	"github.com/andreabedini/clatto/internal/config"
	"github.com/andreabedini/clatto/internal/daemon"
	"github.com/andreabedini/clatto/internal/netconf"
	"github.com/andreabedini/clatto/internal/observe"
)

// version is set at build time with -ldflags "-X main.version=...".
var version = "dev"

const fileWatchInterval = 2 * time.Second

func main() {
	os.Exit(run())
}

func run() int {
	defaultPath := os.Getenv(config.EnvPrefix + "CONFIG")
	if defaultPath == "" {
		defaultPath = config.DefaultConfigPath
	}
	var (
		configPath  = flag.String("config", defaultPath, "configuration file (YAML); a missing default file is ignored")
		check       = flag.Bool("check", false, "validate the configuration and exit")
		printConfig = flag.Bool("print-config", false, "print the effective configuration as YAML and exit")
		showVersion = flag.Bool("version", false, "print the version and exit")
		noWatch     = flag.Bool("no-watch", false, "do not reload when the configuration file changes")
		probe       = flag.String("probe", "", "request this path (e.g. /readyz) from the admin listener of the configured instance and exit 0 on success; for exec probes")
	)
	flag.Parse()
	if *showVersion {
		fmt.Println("clatto", version)
		return 0
	}

	bootLog := slog.New(slog.NewTextHandler(os.Stderr, nil))
	explicit := *configPath != defaultPath

	// load reads the file (if present) and the environment.
	load := func() (config.Config, error) {
		var cfg config.Config
		if err := config.LoadFile(&cfg, *configPath); err != nil {
			if explicit || !errors.Is(err, os.ErrNotExist) {
				return cfg, fmt.Errorf("load %s: %w", *configPath, err)
			}
		}
		if err := config.LoadEnv(&cfg, os.LookupEnv); err != nil {
			return cfg, fmt.Errorf("environment: %w", err)
		}
		return cfg, nil
	}

	cfg, err := load()
	if err != nil {
		bootLog.Error("configuration", "error", err)
		return 2
	}
	resolved, err := config.ResolveWith(cfg, config.ResolveOptions{SourceAddr: netconf.SourceAddress})
	if err != nil {
		bootLog.Error("invalid configuration", "error", err)
		return 2
	}
	if *probe != "" {
		if resolved.HTTPListen == "" {
			bootLog.Error("probe", "error", "the admin listener is off")
			return 2
		}
		return runProbe(probeURL(resolved.HTTPListen, *probe))
	}
	if *check {
		fmt.Println("configuration ok")
		for _, w := range resolved.Warnings {
			fmt.Println("warning:", w)
		}
		return 0
	}
	if *printConfig {
		data, err := config.Marshal(resolved.Config)
		if err != nil {
			bootLog.Error("marshal configuration", "error", err)
			return 1
		}
		os.Stdout.Write(data)
		return 0
	}

	// Logging: the level can change on reload, the format cannot.
	level := new(slog.LevelVar)
	level.Set(resolved.LogLevel)
	opts := &slog.HandlerOptions{Level: level}
	var handler slog.Handler
	if resolved.LogJSON {
		handler = slog.NewJSONHandler(os.Stdout, opts)
	} else {
		handler = slog.NewTextHandler(os.Stdout, opts)
	}
	log := slog.New(handler)
	slog.SetDefault(log)
	log.Info("starting clatto", "version", version, "config", *configPath)
	for _, w := range resolved.Warnings {
		log.Warn(w)
	}
	for _, e := range resolved.Table.Entries() {
		log.Info("mapping", "entry", e.String())
	}
	log.Info("translator addresses", "ipv4", resolved.Xlate.LocalAddr4, "ipv6", resolved.Xlate.LocalAddr6)

	reg := prometheus.NewRegistry()
	reg.MustRegister(collectors.NewGoCollector(), collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}))
	observe.RegisterBuildInfo(reg, version)

	d := daemon.New(resolved, daemon.Options{Log: log, Level: level, Registry: reg, LoadFile: load})

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// Admin server starts first so liveness works while the tun is set up.
	adminErr := make(chan error, 1)
	if resolved.HTTPListen != "" {
		srv := admin.New(reg, version, d, resolved.Config.HTTP.Admin)
		go func() { adminErr <- srv.Serve(ctx, resolved.HTTPListen, log) }()
	}

	// Reload on SIGHUP and on configuration file changes.
	hup := make(chan os.Signal, 1)
	signal.Notify(hup, syscall.SIGHUP)
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case <-hup:
				d.Reload("sighup")
			}
		}
	}()
	if !*noWatch {
		if _, err := os.Stat(*configPath); err == nil {
			go d.WatchFile(ctx, *configPath, fileWatchInterval)
		}
	}

	daemonErr := make(chan error, 1)
	go func() { daemonErr <- d.Run(ctx) }()

	exit := 0
	select {
	case <-ctx.Done():
		log.Info("shutting down")
		if err := <-daemonErr; err != nil {
			log.Error("daemon", "error", err)
			exit = 1
		}
	case err := <-daemonErr:
		if err != nil {
			log.Error("daemon stopped", "error", err)
			exit = 1
		}
		stop()
	case err := <-adminErr:
		log.Error("admin server stopped", "error", err)
		exit = 1
		stop()
		<-daemonErr
	}
	return exit
}

// probeURL turns the listen address into a URL a process in the same
// network namespace can reach: an unspecified host becomes loopback.
func probeURL(listen, path string) string {
	host, port, err := net.SplitHostPort(listen)
	if err != nil {
		host, port = listen, ""
	}
	switch host {
	case "", "0.0.0.0", "::":
		host = "127.0.0.1"
	}
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	return "http://" + net.JoinHostPort(host, port) + path
}

// runProbe fetches url and returns 0 on a 2xx answer, 1 otherwise, printing
// the outcome for the probe log.
func runProbe(url string) int {
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		fmt.Fprintln(os.Stderr, "probe:", err)
		return 1
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	fmt.Printf("%s %s: %s", url, resp.Status, body)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return 1
	}
	return 0
}
