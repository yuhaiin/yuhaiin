package yuhaiin

import "encoding/json/v2"

var (
	AdvAppBypassKey                         = `app_bypass`
	AdvAppListKey                           = `app_list`
	AdvAutoConnectKey                       = `auto_connect`
	AdvBatteryProfileKey                    = `battery_profile`
	AdvNewAppListKey                        = `new_app_list`
	AdvPerAppKey                            = `per_app`
	AdvProcessLookupModeKey                 = `process_lookup_mode`
	AdvRegisterUnderlyingNetworkCallbackKey = `register_underlying_network_callback`
	AdvRouteKey                             = `route`
	AdvRouteAll                             = `All (Default)`
	AdvRouteNonChn                          = `Non-Chinese IPs`
	AdvRouteNonLocal                        = `Non-Local IPs`
	AdvTunDriverKey                         = `Tun Driver`
	AdvUDPIdleProfileKey                    = `udp_idle_profile`
	AdvVPNMTUProfileKey                     = `vpn_mtu_profile`
	AllowLanKey                             = `allow_lan`
	AppendHttpProxyToVpnKey                 = `Append HTTP Proxy to VPN`
	BatteryProfileBalanced                  = `balanced`
	BatteryProfileBatterySaver              = `battery_saver`
	BatteryProfileDiagnostic                = `diagnostic`
	BatteryProfilePerformance               = `performance`
	DnsHijacking                            = `dns_hijacking`
	ProcessLookupAlwaysValue                = `always`
	ProcessLookupOffValue                   = `off`
	ProcessLookupRulesOnlyValue             = `rules_only`
	HttpServerPortKey                       = `http_server_port`
	NetworkSpeedKey                         = `network_speed`
	PortsKey                                = `ports_key`
	SniffKey                                = `Sniff`
	Socks5ServerPortKey                     = `socks5_server_port`
	TunDriverChannelValue                   = `channel`
	TunDriverFdbasedValue                   = `fdbased`
	TunDriverSystemGvisorValue              = `system_gvisor`
	VPNMTU1500Value                         = `1500`
	VPNMTU9000Value                         = `9000`
	VPNMTUAutoValue                         = `auto`
	YuhaiinPortKey                          = `yuhaiin_port`

	AdvRoutes = []string{
		AdvRouteAll,
		AdvRouteNonLocal,
		AdvRouteNonChn,
	}

	TunDriversValue = []string{
		TunDriverFdbasedValue,
		TunDriverChannelValue,
		TunDriverSystemGvisorValue,
	}

	BatteryProfilesValue = []string{
		BatteryProfileBalanced,
		BatteryProfileBatterySaver,
		BatteryProfilePerformance,
		BatteryProfileDiagnostic,
	}

	ProcessLookupModesValue = []string{
		ProcessLookupOffValue,
		ProcessLookupRulesOnlyValue,
		ProcessLookupAlwaysValue,
	}

	VPNMTUProfilesValue = []string{
		VPNMTUAutoValue,
		VPNMTU1500Value,
		VPNMTU9000Value,
	}
)

var (
	NewHTTPPortKey    = "http_port"
	NewYuhaiinPortKey = "yuhaiin_port"
)

var (
	defaultBoolValue = map[string]bool{
		AllowLanKey:                             false,
		AppendHttpProxyToVpnKey:                 false,
		NetworkSpeedKey:                         false,
		AdvAutoConnectKey:                       false,
		AdvPerAppKey:                            false,
		AdvAppBypassKey:                         false,
		AdvRegisterUnderlyingNetworkCallbackKey: true,
		SniffKey:                                true,
		DnsHijacking:                            true,
	}

	disAllowAppList, _ = json.Marshal([]string{
		// RCS/Jibe https://github.com/tailscale/tailscale/issues/2322
		"com.google.android.apps.messaging",
		// Android Auto https://github.com/tailscale/tailscale/issues/3828
		"com.google.android.projection.gearhead",
		// GoPro https://github.com/tailscale/tailscale/issues/2554
		"com.gopro.smarty",
		// Sonos https://github.com/tailscale/tailscale/issues/2548
		"com.sonos.acr",
		"com.sonos.acr2",
		// Google Chromecast https://github.com/tailscale/tailscale/issues/3636
		"com.google.android.apps.chromecast.app",
		// Voicemail https://github.com/tailscale/tailscale/issues/13199
		"com.samsung.attvvm",
		"com.att.mobile.android.vvm",
		"com.tmobile.vvm.application",
		"com.metropcs.service.vvm",
		"com.mizmowireless.vvm",
		"com.vna.service.vvm",
		"com.dish.vvm",
		"com.comcast.modesto.vvm.client",
		// Android Connectivity Service https://github.com/tailscale/tailscale/issues/14128
		"com.google.android.apps.scone",

		// myself
		"io.github.yuhaiin",
	})

	defaultStringValue = map[string]string{
		AdvRouteKey:             AdvRoutes[0],
		AdvTunDriverKey:         TunDriversValue[2],
		AdvAppListKey:           string(disAllowAppList),
		AdvBatteryProfileKey:    BatteryProfileBalanced,
		AdvProcessLookupModeKey: ProcessLookupAlwaysValue,
		AdvUDPIdleProfileKey:    BatteryProfileBalanced,
		AdvVPNMTUProfileKey:     VPNMTUAutoValue,
	}

	defaultIntValue = map[string]int32{
		NewHTTPPortKey:    0,
		NewYuhaiinPortKey: 3500,
	}
)
