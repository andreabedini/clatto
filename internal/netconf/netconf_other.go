//go:build !linux

package netconf

import (
	"errors"
	"log/slog"
	"net/netip"
)

// Options describes the desired state.
type Options struct {
	Name      string
	Addresses []netip.Prefix
	Routes4   []netip.Prefix
	Routes6   []netip.Prefix
	Sysctl    bool
}

// Apply is not supported on this platform.
func Apply(Options, *slog.Logger) error {
	return errors.New("interface configuration is only supported on Linux")
}
