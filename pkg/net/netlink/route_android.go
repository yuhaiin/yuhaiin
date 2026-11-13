package netlink

// ConfigureTun is a no-op: the Android VpnService configures its interface.
func ConfigureTun(opt *Options) (func(), error) {
	return nil, nil
}

func SetNoqueue(iface string) error {
	return nil
}

// Android routes belong to the VpnService and are applied through the
// platform VPN adapter instead.
func newPlatformRouteBackend() (routeBackend, error) { return nil, ErrRoutesUnsupported }
