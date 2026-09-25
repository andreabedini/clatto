// Command clatto is a stateless NAT64 / CLAT translator built to run as a
// Kubernetes sidecar.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"

	"github.com/andreabedini/clatto/internal/admin"
	"github.com/andreabedini/clatto/internal/config"
	"github.com/andreabedini/clatto/internal/netconf"
	"github.com/andreabedini/clatto/internal/observe"
	"github.com/andreabedini/clatto/internal/tundev"
	"github.com/andreabedini/clatto/internal/xlate"
)

// version is set at build time with -ldflags "-X main.version=...".
var version = "dev"

const (
	poolMaintainInterval = 45 * time.Second
)

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
	)
	flag.Parse()
	if *showVersion {
		fmt.Println("clatto", version)
		return 0
	}

	bootLog := slog.New(slog.NewTextHandler(os.Stderr, nil))

	var cfg config.Config
	explicit := *configPath != defaultPath
	if err := config.LoadFile(&cfg, *configPath); err != nil {
		if explicit || !errors.Is(err, os.ErrNotExist) {
			bootLog.Error("load configuration file", "path", *configPath, "error", err)
			return 2
		}
	}
	if err := config.LoadEnv(&cfg, os.LookupEnv); err != nil {
		bootLog.Error("environment configuration", "error", err)
		return 2
	}
	resolved, err := config.Resolve(cfg, nil)
	if err != nil {
		bootLog.Error("invalid configuration", "error", err)
		return 2
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

	// Logging.
	var handler slog.Handler
	opts := &slog.HandlerOptions{Level: resolved.LogLevel}
	if resolved.LogJSON {
		handler = slog.NewJSONHandler(os.Stdout, opts)
	} else {
		handler = slog.NewTextHandler(os.Stdout, opts)
	}
	log := slog.New(handler)
	slog.SetDefault(log)
	log.Info("starting clatto", "version", version)
	for _, w := range resolved.Warnings {
		log.Warn(w)
	}
	for _, e := range resolved.Table.Entries() {
		log.Info("mapping", "entry", e.String())
	}
	log.Info("translator addresses", "ipv4", resolved.Xlate.LocalAddr4, "ipv6", resolved.Xlate.LocalAddr6)

	// Observers.
	reg := prometheus.NewRegistry()
	reg.MustRegister(collectors.NewGoCollector(), collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}))
	observe.RegisterBuildInfo(reg, version)
	metrics := observe.NewMetrics(reg)
	obs := xlate.MultiObserver{metrics, observe.NewPacketLogger(log, resolved.PacketKinds)}
	if resolved.Pool != nil {
		resolved.Pool.SetObserver(obs)
		observe.RegisterPool(reg, resolved.Pool)
		if sf := resolved.Config.DynamicPool.StateFile; sf != "" {
			n, err := resolved.Pool.Load(sf)
			if err != nil {
				log.Error("load dynamic pool state", "path", sf, "error", err)
			} else {
				log.Info("loaded dynamic pool state", "path", sf, "entries", n)
			}
		}
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// Admin server starts first so liveness works while the tun is set up.
	adm := admin.New(reg, version, func() ([]byte, error) { return config.Marshal(resolved.Config) })
	adminErr := make(chan error, 1)
	if resolved.HTTPListen != "" {
		go func() { adminErr <- adm.Serve(ctx, resolved.HTTPListen, log) }()
	}

	// Tun device and kernel configuration.
	dev, err := tundev.Create(resolved.Config.Interface.Name, resolved.Config.Interface.MTU)
	if err != nil {
		log.Error("create tun device", "name", resolved.Config.Interface.Name, "error", err,
			"hint", "the container needs CAP_NET_ADMIN and access to /dev/net/tun")
		return 1
	}
	name, _ := dev.Name()
	log.Info("tun device created", "name", name, "mtu", resolved.Config.Interface.MTU, "batch", dev.BatchSize())
	if resolved.Configure() {
		err := netconf.Apply(netconf.Options{
			Name:      name,
			Addresses: resolved.Config.Interface.Addresses,
			Routes4:   resolved.Routes4,
			Routes6:   resolved.Routes6,
			Sysctl:    resolved.Sysctl(),
		}, log)
		if err != nil {
			log.Error("configure interface", "error", err)
			dev.Close()
			return 1
		}
	} else {
		log.Info("interface configuration disabled; bring the link up and add routes yourself")
	}

	translator := xlate.New(resolved.Xlate, resolved.Table, obs)
	eng := tundev.NewEngine(dev, translator, log)
	observe.RegisterEngine(reg, eng)
	engineErr := make(chan error, 1)
	go func() { engineErr <- eng.Run(ctx) }()
	adm.SetReady(true)
	log.Info("translating")

	// Dynamic pool maintenance and persistence.
	maintDone := make(chan struct{})
	go func() {
		defer close(maintDone)
		if resolved.Pool == nil {
			return
		}
		sf := resolved.Config.DynamicPool.StateFile
		t := time.NewTicker(poolMaintainInterval)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				resolved.Pool.Maintain()
				if sf != "" && resolved.Pool.Dirty() {
					if err := resolved.Pool.Save(sf); err != nil {
						log.Error("save dynamic pool state", "path", sf, "error", err)
					}
				}
			}
		}
	}()

	exit := 0
	select {
	case <-ctx.Done():
		log.Info("shutting down")
	case err := <-engineErr:
		log.Error("packet engine stopped", "error", err)
		exit = 1
		stop()
	case err := <-adminErr:
		log.Error("admin server stopped", "error", err)
		exit = 1
		stop()
	}
	adm.SetReady(false)
	<-maintDone
	if err := <-engineErr; err != nil && !errors.Is(err, context.Canceled) {
		log.Error("packet engine", "error", err)
	}
	if resolved.Pool != nil {
		if sf := resolved.Config.DynamicPool.StateFile; sf != "" {
			if err := resolved.Pool.Save(sf); err != nil {
				log.Error("save dynamic pool state", "path", sf, "error", err)
			}
		}
	}
	return exit
}
