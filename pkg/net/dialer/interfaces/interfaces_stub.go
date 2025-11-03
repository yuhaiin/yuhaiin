//go:build (!linux || android) && !darwin && !windows

package interfaces

import (
	"errors"
)

func defaultRoute() (d DefaultRouteDetails, err error) {
	return d, errors.ErrUnsupported
}

func startMonitor(onChange func(string)) NetworkMonitor { return stubNetworkMonitor{} }

type stubNetworkMonitor struct{}

func (stubNetworkMonitor) Stop() error { return nil }
