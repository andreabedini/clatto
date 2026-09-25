#!/bin/sh
# Runs the end-to-end test in a fresh network namespace.
#
# Needs /dev/net/tun and either root (sudo test/e2e.sh) or unprivileged
# user namespaces. The test binary is compiled before entering the
# namespace, which has no network access.
set -eu
cd "$(dirname "$0")/.."
bin="${TMPDIR:-/tmp}/clatto-e2e.test"
go test -c -tags e2e -o "$bin" ./test/
trap 'rm -f "$bin"' EXIT
if [ "$(id -u)" = 0 ]; then
	unshare -n "$bin" -test.v "$@"
else
	unshare -Urn "$bin" -test.v "$@"
fi
