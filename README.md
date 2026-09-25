# clatto

clatto is a stateless NAT64 and CLAT translator (RFC 7915, RFC 6052,
RFC 6877) written in Go. It is a drop-in replacement for
[tayga](https://github.com/apalrd/tayga) built for containers and Kubernetes
sidecars:

- one static binary, distroless image, no scripts around it: clatto creates
  the tun device, brings it up, installs routes and enables forwarding itself;
- configuration from a YAML file (a ConfigMap) with `CLATTO_*` environment
  overrides;
- JSON logs on stdout, `/healthz`, `/readyz` and Prometheus `/metrics`;
- the same address mapping semantics as tayga: an RFC 6052 prefix, static
  maps and a dynamic pool with persistent leases (tayga's `dynamic.map` files
  load unchanged).

## Running

```sh
CLATTO_IPV4_ADDRESS=192.168.255.1 \
CLATTO_PREFIX=64:ff9b::/96 \
CLATTO_DYNAMIC_POOL=192.168.255.0/24 \
clatto
```

or with a file:

```sh
clatto -config /etc/clatto/config.yaml
clatto -config /etc/clatto/config.yaml -check         # validate only
clatto -config /etc/clatto/config.yaml -print-config  # effective YAML
```

The process needs `CAP_NET_ADMIN` and `/dev/net/tun`. See
[examples/config.yaml](examples/config.yaml) for every option,
[examples/clat.yaml](examples/clat.yaml) for a CLAT and
[examples/k8s-sidecar.yaml](examples/k8s-sidecar.yaml) for a pod.

## Configuration

| YAML | Environment | Meaning |
| --- | --- | --- |
| `interface.name` | `CLATTO_INTERFACE` | tun device name (default `clat0`) |
| `interface.mtu` | `CLATTO_MTU` | MTU (default 1500) |
| `interface.configure` | `CLATTO_INTERFACE_CONFIGURE` | link up, addresses, routes, sysctls (default true) |
| `interface.auto_routes` | `CLATTO_INTERFACE_AUTO_ROUTES` | route every mapped prefix via the device (default true) |
| `interface.sysctl` | `CLATTO_INTERFACE_SYSCTL` | enable IPv4 and IPv6 forwarding (default true) |
| `interface.addresses` | `CLATTO_INTERFACE_ADDRESSES` | addresses to assign to the device |
| `interface.routes` | `CLATTO_INTERFACE_ROUTES` | extra routes via the device |
| `ipv4_address` | `CLATTO_IPV4_ADDRESS` | the translator's IPv4 address (required) |
| `ipv6_address` | `CLATTO_IPV6_ADDRESS` | the translator's IPv6 address (derived from the prefix if omitted) |
| `prefix` | `CLATTO_PREFIX` | NAT64 prefix |
| `wkpf_strict` | `CLATTO_WKPF_STRICT` | forbid private IPv4 through `64:ff9b::/96` (default true) |
| `maps` | `CLATTO_MAPS` | static maps; env form `v4=v6,v4/24=v6/120` |
| `dynamic_pool.prefix` | `CLATTO_DYNAMIC_POOL` | IPv4 pool for unmapped IPv6 hosts |
| `dynamic_pool.state_file` | `CLATTO_DYNAMIC_POOL_STATE_FILE` | persist pool assignments (`$STATE_DIRECTORY/dynamic.map` under systemd) |
| `udp_checksum` | `CLATTO_UDP_CHECKSUM` | `drop`, `calc` or `forward` (default drop) |
| `offlink_mtu` | `CLATTO_OFFLINK_MTU` | fragment IPv6 output above this size (default 1280) |
| `log.level`, `log.format` | `CLATTO_LOG_LEVEL`, `CLATTO_LOG_FORMAT` | `info`/`debug`/..., `json`/`text` |
| `log.packets` | `CLATTO_LOG_PACKETS` | log packet events: `drop reject icmp self dynamic` |
| `http.listen` | `CLATTO_HTTP_LISTEN` | admin listener (default `:6464`, `off` disables) |

`CLATTO_CONFIG` names the file (default `/etc/clatto/config.yaml`) and
`CLATTO_CONFIG_YAML` can carry a whole document inline. Precedence is
defaults, file, environment.

## Metrics

- `clatto_translated_packets_total{direction}` and `..._bytes_total`
- `clatto_packet_events_total{family,kind,reason}` for drops, rejects,
  generated ICMP and self-addressed packets
- `clatto_dynamic_pool_{size,mapped,dormant}`
- `clatto_tun_{packets,bytes}_{received,sent}_total`, `clatto_tun_{read,write}_errors_total`

## Building

```sh
go build ./cmd/clatto
podman build -t clatto .
go test ./...
test/e2e.sh        # real tun device in a throwaway network namespace (no root needed)
```

## License

GPL-2.0-or-later. The translation logic is a port of tayga by Nathan
Lutchansky and Andrew Palardy.
