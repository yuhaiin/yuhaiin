package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"

	core "github.com/Asutorufa/yuhaiin/cmd/android"
)

func logWarn(msg string, err error) { slog.Warn(msg, "err", err) }

// The core is a process-wide singleton: Android runs exactly one in ":bg".
var app = &core.App{}

// Operations (yh_call). Requests and responses are JSON unless marked raw.
//
//	core.init            {savePath, configLockPath, managementTLSDir}
//	core.start           {}
//	core.stop            {}
//	core.session         {} -> {running, port, token}
//	core.native_status   {} -> raw JSON
//	core.health          {} -> raw JSON
//	core.monitoring      {online, metered, foreground}
//	core.vpn_enabled     {} -> {enabled}
//	core.set_vpn_enabled {enabled}
//	vpn.status           {} -> raw JSON
//	vpn.revoked          {generation} -> {applied}
//	vpn.reconfigure      {}
//	network.report       {selected, networks[]}
//	net.is_ipv6          {} -> {ipv6}
//	net.parse_cidr       {cidrs[]} -> {prefixes[{ip,mask}]}
//	store.get            {keys[{key,type}]} -> {values[]}
//	store.put            {entries[{key,type,value}]}
//	config.export        {} -> raw backup bytes
//	config.validate      raw backup bytes
//	config.import        raw backup bytes
//	proxy.get            {url} -> raw bytes
//	proxy.download       {url, destination}
func init() {
	register("core.init", jsonOp(coreInit))
	register("core.start", jsonOp(coreStart))
	register("core.stop", jsonOp(coreStop))
	register("core.session", jsonOp(coreSession))
	register("core.native_status", rawOut(func() (string, error) { return app.NativeStatus() }))
	register("core.health", rawOut(func() (string, error) { return app.CheckHealth() }))
	register("core.monitoring", jsonOp(coreMonitoring))
	register("core.vpn_enabled", jsonOp(func(empty) (map[string]bool, error) {
		return map[string]bool{"enabled": app.VpnEnabled()}, nil
	}))
	register("core.set_vpn_enabled", jsonOp(func(r struct {
		Enabled bool `json:"enabled"`
	}) (empty, error) {
		return empty{}, app.SetVpnEnabled(r.Enabled)
	}))
	register("vpn.status", rawOut(func() (string, error) { return core.VpnStatus(), nil }))
	register("vpn.revoked", jsonOp(func(r struct {
		Generation int64 `json:"generation"`
	}) (map[string]bool, error) {
		return map[string]bool{"applied": core.NotifyVpnRevoked(r.Generation)}, nil
	}))
	register("vpn.reconfigure", jsonOp(func(empty) (empty, error) {
		core.RequestVpnReconfigure()
		return empty{}, nil
	}))
	register("network.report", jsonOp(networkReport))
	register("net.is_ipv6", jsonOp(func(empty) (map[string]bool, error) {
		return map[string]bool{"ipv6": core.IsIPv6()}, nil
	}))
	register("net.parse_cidr", jsonOp(parseCIDRs))
	register("store.get", jsonOp(storeGet))
	register("store.put", jsonOp(storePut))
	register("config.export", func([]byte) ([]byte, error) { return core.ExportConfig() })
	register("config.validate", func(b []byte) ([]byte, error) { return nil, core.ValidateConfig(b) })
	register("config.import", func(b []byte) ([]byte, error) { return nil, core.ImportConfig(b) })
	register("proxy.get", jsonOpRaw(func(r struct {
		URL string `json:"url"`
	}) ([]byte, error) {
		return core.ProxyGet(r.URL)
	}))
	register("proxy.download", jsonOp(func(r struct {
		URL         string `json:"url"`
		Destination string `json:"destination"`
	}) (empty, error) {
		return empty{}, core.ProxyDownload(r.URL, r.Destination)
	}))
}

// rawOut adapts a handler that ignores its request and returns a string.
func rawOut(fn func() (string, error)) operation {
	return func([]byte) ([]byte, error) {
		s, err := fn()
		if err != nil {
			return nil, err
		}
		return []byte(s), nil
	}
}

// jsonOpRaw decodes a JSON request and returns raw bytes.
func jsonOpRaw[Req any](fn func(Req) ([]byte, error)) operation {
	return func(raw []byte) ([]byte, error) {
		req, err := decode[Req](raw)
		if err != nil {
			return nil, err
		}
		return fn(req)
	}
}

// ---- lifecycle ----

func coreInit(r struct {
	SavePath         string `json:"savePath"`
	ConfigLockPath   string `json:"configLockPath"`
	ManagementTLSDir string `json:"managementTLSDir"`
}) (empty, error) {
	if r.SavePath == "" {
		return empty{}, badRequestError{errors.New("savePath is required")}
	}
	if app.Running() {
		return empty{}, errors.New("core is running")
	}
	core.SetSavePath(r.SavePath)
	core.SetConfigLockPath(r.ConfigLockPath)
	core.SetManagementTLSDir(r.ManagementTLSDir)
	return empty{}, nil
}

func coreStart(empty) (empty, error) {
	coreActive.Store(true)
	opts := &core.Opts{
		CloseFallback: closeFunc(func() error {
			// The host handler only schedules work; it never blocks the core.
			if _, err := hostCall("core.closed", nil); err != nil && !errors.Is(err, errNoHost) {
				logWarn("core.closed failed", err)
			}
			return nil
		}),
		TUN: &core.TUN{SocketBind: sockets{}, SocketProtect: sockets{}},
	}
	if err := app.Start(opts); err != nil {
		coreActive.Store(false)
		return empty{}, err
	}
	return empty{}, nil
}

func coreStop(empty) (empty, error) {
	err := app.Stop()
	if !app.Running() {
		coreActive.Store(false)
	}
	return empty{}, err
}

func coreSession(empty) (map[string]any, error) {
	running := app.Running()
	out := map[string]any{"running": running, "port": int32(0), "token": ""}
	if running {
		out["port"] = app.HTTPPort()
		out["token"] = app.PlatformToken()
	}
	return out, nil
}

func coreMonitoring(r struct {
	Online     bool `json:"online"`
	Metered    bool `json:"metered"`
	Foreground bool `json:"foreground"`
}) (empty, error) {
	return empty{}, app.SetMonitoringNetworkState(r.Online, r.Metered, r.Foreground)
}

// ---- network ----

type networkJSON struct {
	Handle         int64  `json:"handle"`
	InterfaceIndex int32  `json:"interfaceIndex"`
	InterfaceName  string `json:"interfaceName"`
	Addresses      string `json:"addresses"`
	Available      bool   `json:"available"`
	Validated      bool   `json:"validated"`
	Vpn            bool   `json:"vpn"`
}

func networkReport(r struct {
	Selected int64         `json:"selected"`
	Networks []networkJSON `json:"networks"`
}) (empty, error) {
	it := &networkIter{}
	for _, n := range r.Networks {
		it.items = append(it.items, &core.UnderlyingNetwork{
			Handle: n.Handle, InterfaceIndex: n.InterfaceIndex, InterfaceName: n.InterfaceName,
			Addresses: n.Addresses, Available: n.Available, Validated: n.Validated, Vpn: n.Vpn,
		})
	}
	return empty{}, core.ReportUnderlyingNetworks(it, r.Selected)
}

func parseCIDRs(r struct {
	CIDRs []string `json:"cidrs"`
}) (map[string][]map[string]any, error) {
	out := make([]map[string]any, 0, len(r.CIDRs))
	for _, c := range r.CIDRs {
		_, n, err := net.ParseCIDR(c)
		if err != nil {
			return nil, err
		}
		ones, _ := n.Mask.Size()
		out = append(out, map[string]any{"ip": n.IP.String(), "mask": ones})
	}
	return map[string][]map[string]any{"prefixes": out}, nil
}

// ---- store ----

type storeKey struct {
	Key  string `json:"key"`
	Type string `json:"type"`
}

func storeGet(r struct {
	Keys []storeKey `json:"keys"`
}) (map[string][]any, error) {
	s := core.GetStore()
	values := make([]any, 0, len(r.Keys))
	for _, k := range r.Keys {
		switch k.Type {
		case "string":
			values = append(values, s.GetString(k.Key))
		case "int":
			values = append(values, s.GetInt(k.Key))
		case "bool":
			values = append(values, s.GetBoolean(k.Key))
		case "long":
			values = append(values, s.GetLong(k.Key))
		case "float":
			values = append(values, s.GetFloat(k.Key))
		case "bytes":
			values = append(values, s.GetBytes(k.Key))
		default:
			return nil, badRequestError{fmt.Errorf("unknown store type %q", k.Type)}
		}
	}
	return map[string][]any{"values": values}, nil
}

func storePut(r struct {
	Entries []struct {
		storeKey
		Value json.RawMessage `json:"value"`
	} `json:"entries"`
}) (empty, error) {
	s := core.GetStore()
	// Validate everything first so a bad entry does not leave a partial write.
	apply := make([]func(), 0, len(r.Entries))
	for _, e := range r.Entries {
		key, raw := e.Key, e.Value
		switch e.Type {
		case "string":
			var v string
			if err := json.Unmarshal(raw, &v); err != nil {
				return empty{}, badRequestError{err}
			}
			apply = append(apply, func() { s.PutString(key, v) })
		case "int":
			var v int32
			if err := json.Unmarshal(raw, &v); err != nil {
				return empty{}, badRequestError{err}
			}
			apply = append(apply, func() { s.PutInt(key, v) })
		case "bool":
			var v bool
			if err := json.Unmarshal(raw, &v); err != nil {
				return empty{}, badRequestError{err}
			}
			apply = append(apply, func() { s.PutBoolean(key, v) })
		case "long":
			var v int64
			if err := json.Unmarshal(raw, &v); err != nil {
				return empty{}, badRequestError{err}
			}
			apply = append(apply, func() { s.PutLong(key, v) })
		case "float":
			var v float32
			if err := json.Unmarshal(raw, &v); err != nil {
				return empty{}, badRequestError{err}
			}
			apply = append(apply, func() { s.PutFloat(key, v) })
		case "bytes":
			var v []byte
			if err := json.Unmarshal(raw, &v); err != nil {
				return empty{}, badRequestError{err}
			}
			apply = append(apply, func() { s.PutBytes(key, v) })
		default:
			return empty{}, badRequestError{fmt.Errorf("unknown store type %q", e.Type)}
		}
	}
	for _, f := range apply {
		f()
	}
	return empty{}, nil
}
