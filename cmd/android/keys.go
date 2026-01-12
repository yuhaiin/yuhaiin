package yuhaiin

import "encoding/json/v2"

var (
	NewHTTPPortKey    = "http_port"
	NewYuhaiinPortKey = "yuhaiin_port"
)

var (
	defaultBoolValue = map[string]bool{
		AllowLanKey:             false,
		AppendHttpProxyToVpnKey: false,
		NetworkSpeedKey:         false,
		AdvAutoConnectKey:       false,
		AdvPerAppKey:            false,
		AdvAppBypassKey:         false,
		SniffKey:                true,
		DnsHijacking:            true,
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
		AdvRouteKey:     AdvRoutes[0],
		AdvTunDriverKey: TunDriversValue[2],
		AdvAppListKey:   string(disAllowAppList),
	}

	defaultIntValue = map[string]int32{
		NewHTTPPortKey:    0,
		NewYuhaiinPortKey: 3500,
	}

	defaultLongValue  = map[string]int64{}
	defaultFloatValue = map[string]float32{}
)
