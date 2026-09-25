#!/bin/sh
# Compares clatto with tayga on the same traffic, each in turn, in a fresh
# network namespace: UDP blasts of several sizes and TCP streams from an
# IPv6 client to an IPv4 server through the translator. Reports what got
# through and the translator's CPU time per packet or per megabyte.
#
#   test/bench.sh [path/to/tayga]        # tayga defaults to $TAYGA or $PATH
#   DURATION=10 FLOWS="1 4" test/bench.sh
#
# Needs /dev/net/tun and either root or unprivileged user namespaces, like
# test/e2e.sh. Without a tayga binary only clatto is measured.
set -eu
cd "$(dirname "$0")/.."
tmp=$(mktemp -d "${TMPDIR:-/tmp}/clatto-bench.XXXXXX")
trap 'rm -rf "$tmp"' EXIT
TAYGA="${1:-${TAYGA:-$(command -v tayga || true)}}"
export TAYGA DURATION="${DURATION:-5}" FLOWS="${FLOWS:-1 4}" SIZES="${SIZES:-64 512 1400}"

go build -o "$tmp/clatto" ./cmd/clatto
go build -o "$tmp/bench" ./test/bench

cat > "$tmp/clatto.yaml" <<'EOF'
interface: {name: bench0, sysctl: false}
ipv4_address: 10.0.0.254
ipv6_address: 2001:db8::fe
prefix: 64:ff9b::/96
wkpf_strict: false
maps:
  - {ipv4: 10.0.0.2, ipv6: 2001:db8::1}
log: {level: warn}
http: {listen: off}
EOF
cat > "$tmp/tayga.conf" <<'EOF'
tun-device bench0
ipv4-addr 10.0.0.254
ipv6-addr 2001:db8::fe
prefix 64:ff9b::/96
wkpf-strict no
map 10.0.0.2 2001:db8::1
EOF

cat > "$tmp/inner.sh" <<'EOF'
set -eu
tmp=$1
ip link set lo up
ip addr add 2001:db8::1/128 dev lo
ip addr add 10.0.0.1/32 dev lo

wait_for_link() {
	i=0
	while ! ip link show bench0 >/dev/null 2>&1 || ! ip -6 route show dev bench0 | grep -q 64:ff9b; do
		i=$((i + 1))
		[ "$i" -lt 100 ] || { echo "bench0 did not come up" >&2; exit 1; }
		sleep 0.05
	done
}

measure() {
	name=$1 pid=$2
	for flows in $FLOWS; do
		for size in $SIZES; do
			"$tmp/bench" -translator "$name" -proto udp -size "$size" -flows "$flows" -duration "${DURATION}s" -pid "$pid"
		done
	done
	for flows in $FLOWS; do
		"$tmp/bench" -translator "$name" -proto tcp -flows "$flows" -duration "${DURATION}s" -pid "$pid"
	done
}

echo "== clatto ($("$tmp/clatto" -version))"
"$tmp/clatto" -config "$tmp/clatto.yaml" -no-watch &
pid=$!
wait_for_link
measure clatto "$pid"
kill "$pid"
wait "$pid" 2>/dev/null || true

if [ -n "$TAYGA" ]; then
	echo "== tayga ($TAYGA)"
	"$TAYGA" --config "$tmp/tayga.conf" --mktun >/dev/null
	ip link set bench0 up
	ip -6 route add 64:ff9b::/96 dev bench0
	ip -4 route add 10.0.0.2/32 dev bench0
	ip -4 route add 10.0.0.254/32 dev bench0
	"$TAYGA" --config "$tmp/tayga.conf" --nodetach --stdout >/dev/null 2>&1 &
	pid=$!
	wait_for_link
	sleep 0.2
	measure tayga "$pid"
	kill "$pid"
	wait "$pid" 2>/dev/null || true
	ip link del bench0
else
	echo "== tayga: no binary found (pass its path or set TAYGA), skipped"
fi
EOF

if [ "$(id -u)" = 0 ]; then
	unshare -n sh "$tmp/inner.sh" "$tmp"
else
	unshare -Urn sh "$tmp/inner.sh" "$tmp"
fi
