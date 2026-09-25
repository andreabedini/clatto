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
clatto -config /etc/clatto/config.yaml -probe /readyz  # exec probe against the running instance
```

The process needs `CAP_NET_ADMIN` and `/dev/net/tun`. See
[examples/config.yaml](examples/config.yaml) for every option,
[examples/clat.yaml](examples/clat.yaml) for a CLAT with a dedicated
address, [examples/clat-shared.yaml](examples/clat-shared.yaml) for a CLAT
sharing the host's address, and [examples/k8s-sidecar.yaml](examples/k8s-sidecar.yaml)
and [examples/k8s-clat-sidecar.yaml](examples/k8s-clat-sidecar.yaml) for
pods.

## Configuration

| YAML | Environment | Meaning |
| --- | --- | --- |
| `interface.name` | `CLATTO_INTERFACE` | tun device name (default `clat0`) |
| `interface.mtu` | `CLATTO_MTU` | MTU (default 1500) |
| `interface.configure` | `CLATTO_INTERFACE_CONFIGURE` | link up, addresses, routes, sysctls (default true) |
| `interface.auto_routes` | `CLATTO_INTERFACE_AUTO_ROUTES` | route every mapped prefix via the device (default true) |
| `interface.sysctl` | `CLATTO_INTERFACE_SYSCTL` | enable IPv4 and IPv6 forwarding (default true; IPv6 only in CLAT mode) |
| `interface.addresses` | `CLATTO_INTERFACE_ADDRESSES` | addresses to assign to the device |
| `interface.routes` | `CLATTO_INTERFACE_ROUTES` | extra routes via the device: a prefix, or `{prefix, metric, mtu, advmss}`; one replaces the automatic route for the same prefix |
| `ipv4_address` | `CLATTO_IPV4_ADDRESS` | the translator's IPv4 address (required) |
| `ipv6_address` | `CLATTO_IPV6_ADDRESS` | the translator's IPv6 address (derived from the prefix if omitted) |
| `prefix` | `CLATTO_PREFIX` | NAT64 prefix |
| `wkpf_strict` | `CLATTO_WKPF_STRICT` | forbid private IPv4 through `64:ff9b::/96` (default true) |
| `maps` | `CLATTO_MAPS` | static maps; env form `v4=v6,v4/24=v6/120` |
| `dynamic_pool.prefix` | `CLATTO_DYNAMIC_POOL` | IPv4 pool for unmapped IPv6 hosts |
| `dynamic_pool.state_file` | `CLATTO_DYNAMIC_POOL_STATE_FILE` | persist pool assignments (`$STATE_DIRECTORY/dynamic.map` under systemd) |
| `clat` | `CLATTO_CLAT=true` | CLAT sharing the host's IPv6 address, see below |
| `clat.ipv6_address` | `CLATTO_CLAT_IPV6_ADDRESS` | the shared address, or `auto` (default): the source address towards the prefix |
| `clat.ipv4_address` | `CLATTO_CLAT_IPV4_ADDRESS` | the host's IPv4 address, assigned to the device (default `192.0.0.1`) |
| `clat.ports` | `CLATTO_CLAT_PORTS` | translate only replies to these local ports: `tcp/N-M`, `udp/N`, `icmp` (default: everything from the prefix) |
| `clat.table` | `CLATTO_CLAT_TABLE` | policy routing table (default `0xc1a7`) |
| `udp_checksum` | `CLATTO_UDP_CHECKSUM` | `drop`, `calc` or `forward` (default drop) |
| `offlink_mtu` | `CLATTO_OFFLINK_MTU` | fragment IPv6 output above this size (default 1280) |
| `log.level`, `log.format` | `CLATTO_LOG_LEVEL`, `CLATTO_LOG_FORMAT` | `info`/`debug`/..., `json`/`text` |
| `log.packets` | `CLATTO_LOG_PACKETS` | log packet events: `drop reject icmp self dynamic` |
| `http.listen` | `CLATTO_HTTP_LISTEN` | admin listener (default `:6464`, `off` disables) |
| `http.admin` | `CLATTO_HTTP_ADMIN` | allow configuration changes over HTTP (default false) |

`CLATTO_CONFIG` names the file (default `/etc/clatto/config.yaml`) and
`CLATTO_CONFIG_YAML` can carry a whole document inline. Precedence is
defaults, file, environment.

## CLAT sharing the host's address

A CLAT normally owns a dedicated IPv6 address that the network routes to
it ([examples/clat.yaml](examples/clat.yaml)). A host with a single routed
address, such as a pod on an IPv6-only cluster, has none to spare, so the
`clat` block makes clatto reuse the host's own address, as tayga's
`launch-clat.sh` or clatd's shared mode do:

```yaml
prefix: 64:ff9b::/96
clat:
  ipv6_address: auto
```

With it, clatto:

- maps `clat.ipv4_address` (`192.0.0.1`, assigned to the device) to the
  shared address, and defaults `ipv4_address` to `192.0.0.2`;
- installs an IPv4 default route via the device instead of routing the
  prefix, which stays reachable over the network;
- moves the kernel's IPv6 `local` table rule from priority 0 to 2 and adds
  a rule at priority 1 sending traffic from the prefix to the shared
  address to table `clat.table`, where the address is routed via the
  device. Without this the kernel would deliver the PLAT's replies to its
  own IPv6 stack and the IPv4 side would never see them;
- enables IPv6 forwarding only (a CLAT never forwards IPv4).

Every step is idempotent, so a container restarted in the same network
namespace finds the rules in place and re-adds only what left with the
device. `/readyz` answers once all of it is done, which makes it a startup
probe for the containers that need IPv4.

Replies to the host's own IPv6 connections to NAT64-synthesised addresses
(DNS64) look exactly like CLAT replies, and `clat.ports` is how to tell
them apart: list the local ports the CLAT users bind to, and only those
are translated.

## Reloading and the admin API

The configuration is immutable while it runs and is replaced as a whole.
A replacement is validated first; if it fails, the running configuration
stays and the error is logged and shown in `/config/status`. Anything that
needs the tun device recreated (`interface.name`, `interface.mtu`,
`interface.configure`, `interface.sysctl`, `http.listen`, `log.format`) is
rejected with an explicit error rather than restarting. Everything else,
including routes and the dynamic pool, changes in place; the pool keeps its
assignments when its prefix is unchanged.

Reloads happen on `SIGHUP`, when the configuration file changes (it is
polled every two seconds, which suits ConfigMap volumes; `-no-watch`
disables this) and through the API:

| Endpoint | Purpose |
| --- | --- |
| `GET /healthz`, `GET /readyz` | liveness; readiness once packets flow |
| `GET /metrics` | Prometheus metrics |
| `GET /config` | effective configuration as YAML |
| `GET /config/status` | generation, source and last error as JSON |
| `GET /dynamic` | dynamic pool assignments as JSON |
| `PUT /config` | replace the configuration with the YAML or JSON body (needs `http.admin: true`) |
| `POST /config/reload` | re-read the file and environment (needs `http.admin: true`) |

`PUT /config` takes a complete document, so fetch `/config`, edit, and put
it back. The file and environment are not merged into it. A later file
change replaces it again. Since the listener is normally reachable on the
pod IP, enable `http.admin` only with the listener bound to `127.0.0.1`,
where only containers in the same pod can reach it. The kubelet sends
`httpGet` probes from the node, though, so a loopback listener needs exec
probes instead: `clatto -probe /readyz` requests the path from the
configured listener and exits 0 on success, and the image has no shell or
curl to do it otherwise.

## Metrics

- `clatto_translated_packets_total{direction}` and `..._bytes_total`
- `clatto_packet_events_total{family,kind,reason}` for drops, rejects,
  generated ICMP and self-addressed packets
- `clatto_dynamic_pool_{size,mapped,dormant}`
- `clatto_config_generation`, `clatto_config_reloads_total{source,result}`,
  `clatto_config_last_success_timestamp_seconds`
- `clatto_tun_{packets,bytes}_{received,sent}_total`, `clatto_tun_{read,write}_errors_total`

## Building

```sh
go build ./cmd/clatto
go test ./...
test/e2e.sh        # real tun device in a throwaway network namespace (no root needed)
```

The image is built with [ko](https://ko.build) from `.ko.yaml`: the static
binary on `gcr.io/distroless/static-debian12`, for `linux/amd64` and
`linux/arm64`. CI pushes `ghcr.io/andreabedini/clatto`
tagged `latest`, `main`, `sha-<commit>`, `v1.2.3`/`1.2` for version tags
and `pr-N` for pull requests. Locally:

```sh
ko build --local ./cmd/clatto                                   # into the local daemon
KO_DOCKER_REPO=ghcr.io/you/clatto VERSION=dev ko build --bare ./cmd/clatto
```

## License

GPL-2.0-or-later. The translation logic is a port of tayga by Nathan
Lutchansky and Andrew Palardy.
