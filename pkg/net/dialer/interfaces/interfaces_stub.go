//go:build (!linux || android) && !darwin && !windows

package interfaces

import "fmt"

func defaultRoute() (d DefaultRouteDetails, err error) {
	return d, fmt.Errorf("not implemented")
}
