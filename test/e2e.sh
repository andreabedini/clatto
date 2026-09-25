#!/bin/sh
# Runs the end-to-end test in a fresh network namespace.
#
# Needs /dev/net/tun and either root or unprivileged user namespaces.
set -eu
cd "$(dirname "$0")/.."
if [ "$(id -u)" = 0 ]; then
	exec unshare -n go test -tags e2e -count=1 -v ./test/
fi
exec unshare -Urn go test -tags e2e -count=1 -v ./test/
