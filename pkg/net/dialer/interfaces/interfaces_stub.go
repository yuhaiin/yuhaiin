//go:build (!linux || android) && !darwin && !windows

package interfaces

import (
	"context"
	"errors"
)

func defaultRoute() (d DefaultRouteDetails, err error) {
	return d, errors.ErrUnsupported
}

func startMonitor(ctx context.Context, onChange func(string)) {}
