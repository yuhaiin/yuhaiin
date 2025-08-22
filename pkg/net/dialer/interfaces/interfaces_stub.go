//go:build (!linux || android) && !darwin && !windows

package interfaces

import (
	"context"
	"fmt"
)

func defaultRoute() (d DefaultRouteDetails, err error) {
	return d, fmt.Errorf("not implemented")
}

func startMonitor(ctx context.Context, onChange func()) {}
