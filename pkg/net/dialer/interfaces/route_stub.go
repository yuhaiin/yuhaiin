//go:build (!linux || android) && !darwin && !windows

package interfaces

func routes() (router, error) {
	return router{}, nil
}
