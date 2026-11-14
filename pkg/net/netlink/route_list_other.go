//go:build !(linux && !android) && !darwin && !windows

package netlink

// ListRoutes returns the routes the platform reports through AltListRoutes
// (Android: LinkProperties of each network). There are no policy rules.
func ListRoutes() ([]RouteEntry, []PolicyRuleEntry, error) {
	if AltListRoutes == nil {
		return nil, nil, ErrRouteListUnsupported
	}
	routes, err := AltListRoutes()
	return routes, nil, err
}
