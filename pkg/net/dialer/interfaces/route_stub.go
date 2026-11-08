//go:build (!linux || android) && !darwin && !windows

package interfaces

func routesFrom(map[int]Interface) (router, error) {
	return router{}, nil
}
