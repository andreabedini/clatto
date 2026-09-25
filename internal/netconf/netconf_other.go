//go:build !linux

package netconf

import (
	"errors"
	"log/slog"
	"net/netip"
)

var errUnsupported = errors.New("interface configuration is only supported on Linux")

// Apply is not supported on this platform.
func Apply(Options, *slog.Logger) error { return errUnsupported }

// Update is not supported on this platform.
func Update(Options, Options, *slog.Logger) error { return errUnsupported }

// SourceAddress is not supported on this platform.
func SourceAddress(netip.Addr) (netip.Addr, error) { return netip.Addr{}, errUnsupported }
