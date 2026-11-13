package inbound

// TunRouting is the legacy route selection TUN inbounds used to carry.
// System routes belong to the System Network configuration
// (pkg/contract/sysnet): the core reads these fields only to migrate them
// into System Network rules and then clears them. TUNs ignore them.
type TunRouting struct {
	Mode           string   `json:"mode,omitzero"`
	IncludeCIDRs   []string `json:"includeCidrs,omitzero"`
	BypassCIDRs    []string `json:"bypassCidrs,omitzero"`
	GeoIPCountries []string `json:"geoipCountries,omitzero"`
	GeoIPInvert    bool     `json:"geoipInvert,omitzero"`
}
