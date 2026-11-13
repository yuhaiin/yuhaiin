//go:build !linux && !darwin && !windows

package netlink

func ConfigureTun(*Options) (func(), error) { return nil, nil }

func newPlatformRouteBackend() (routeBackend, error) { return nil, ErrRoutesUnsupported }
