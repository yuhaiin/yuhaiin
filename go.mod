module github.com/Asutorufa/yuhaiin

go 1.25.3

replace (
	github.com/prometheus-community/pro-bing => github.com/Asutorufa/pro-bing v0.0.0-20250716081333-626d07c0d4ca
	github.com/tailscale/wireguard-go => github.com/yuhaiin/wireguard-go v0.0.0-20251018092039-8a0cc74fca62
	golang.zx2c4.com/wintun => github.com/yuhaiin/wintun v0.0.0-20240224105357-b28a4c71608e
	tailscale.com => github.com/Asutorufa/tailscale v0.0.0-20251020171225-a0c076bd101a
)

require (
	github.com/cloudflare/circl v1.6.1
	github.com/godbus/dbus/v5 v5.1.1-0.20241109141217-c266b19b28e9
	github.com/google/nftables v0.3.0
	github.com/libp2p/go-yamux/v5 v5.1.0
	github.com/miekg/dns v1.1.68
	github.com/oschwald/maxminddb-golang/v2 v2.0.0
	github.com/prometheus-community/pro-bing v0.7.0
	github.com/prometheus/client_golang v1.23.2
	github.com/quic-go/quic-go v0.55.0
	github.com/refraction-networking/utls v1.8.1
	github.com/rhnvrm/simples3 v0.10.0
	github.com/tailscale/wireguard-go v0.0.0-20250716170648-1d0488a3d7da
	github.com/vishvananda/netlink v1.3.1
	github.com/xtls/reality v0.0.0-20251014195629-e4eec4520535
	github.com/yuhaiin/yuhaiin.github.io v0.0.0-20251026040108-4211c40e485f
	go.etcd.io/bbolt v1.4.3
	golang.org/x/crypto v0.43.0
	golang.org/x/mobile v0.0.0-20251021151156-188f512ec823
	golang.org/x/net v0.46.1-0.20251024220441-fff0469cf57f
	golang.org/x/sync v0.17.0
	golang.org/x/sys v0.37.0
	golang.org/x/time v0.14.0
	golang.zx2c4.com/wireguard/windows v0.5.4-0.20250318115841-8e6558eba666
	google.golang.org/grpc v1.76.0
	google.golang.org/protobuf v1.36.10
	gvisor.dev/gvisor v0.0.0-20250529183007-2a7b5c7dece9
	tailscale.com v1.9999999999.99999999999
)

require (
	filippo.io/edwards25519 v1.1.0 // indirect
	github.com/akutz/memconn v0.1.0 // indirect
	github.com/alexbrainman/sspi v0.0.0-20231016080023-1a75b4708caa // indirect
	github.com/andybalholm/brotli v1.2.0 // indirect
	github.com/aws/aws-sdk-go-v2 v1.38.3 // indirect
	github.com/aws/aws-sdk-go-v2/config v1.29.17 // indirect
	github.com/beorn7/perks v1.0.1 // indirect
	github.com/cespare/xxhash/v2 v2.3.0 // indirect
	github.com/coder/websocket v1.8.12 // indirect
	github.com/dblohm7/wingoes v0.0.0-20240119213807-a09d6be7affa // indirect
	github.com/francoispqt/gojay v1.2.13 // indirect
	github.com/fxamacker/cbor/v2 v2.7.0 // indirect
	github.com/gaissmai/bart v0.18.0 // indirect
	github.com/go-json-experiment/json v0.0.0-20250813024750-ebf49471dced // indirect
	github.com/golang/groupcache v0.0.0-20210331224755-41bb18bfe9da // indirect
	github.com/google/btree v1.1.2 // indirect
	github.com/google/go-cmp v0.7.0 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/hdevalence/ed25519consensus v0.2.0 // indirect
	github.com/jsimonetti/rtnetlink v1.4.0 // indirect
	github.com/juju/ratelimit v1.0.2 // indirect
	github.com/klauspost/compress v1.18.0 // indirect
	github.com/libp2p/go-buffer-pool v0.1.0 // indirect
	github.com/mdlayher/netlink v1.8.0 // indirect
	github.com/mdlayher/socket v0.5.1 // indirect
	github.com/mitchellh/go-ps v1.0.0 // indirect
	github.com/munnerz/goautoneg v0.0.0-20191010083416-a7dc8b61c822 // indirect
	github.com/pires/go-proxyproto v0.8.1 // indirect
	github.com/prometheus/client_model v0.6.2 // indirect
	github.com/prometheus/common v0.66.1 // indirect
	github.com/prometheus/procfs v0.16.1 // indirect
	github.com/quic-go/qpack v0.5.1 // indirect
	github.com/safchain/ethtool v0.3.0 // indirect
	github.com/tailscale/certstore v0.1.1-0.20231202035212-d3fa0460f47e // indirect
	github.com/tailscale/go-winio v0.0.0-20231025203758-c4f33415bf55 // indirect
	github.com/tailscale/goupnp v1.0.1-0.20210804011211-c64d0f06ea05 // indirect
	github.com/tailscale/hujson v0.0.0-20221223112325-20486734a56a // indirect
	github.com/tailscale/peercred v0.0.0-20250107143737-35a0c7bd7edc // indirect
	github.com/tailscale/web-client-prebuilt v0.0.0-20250124233751-d4cd19a26976 // indirect
	github.com/vishvananda/netns v0.0.5 // indirect
	github.com/x448/float16 v0.8.4 // indirect
	go.uber.org/mock v0.6.0 // indirect
	go.yaml.in/yaml/v2 v2.4.2 // indirect
	go4.org/mem v0.0.0-20240501181205-ae6ca9944745 // indirect
	go4.org/netipx v0.0.0-20231129151722-fdeea329fbba // indirect
	golang.org/x/exp v0.0.0-20250506013437-ce4c2cf36ca6 // indirect
	golang.org/x/mod v0.29.0 // indirect
	golang.org/x/oauth2 v0.30.0 // indirect
	golang.org/x/term v0.36.0 // indirect
	golang.org/x/text v0.30.0 // indirect
	golang.org/x/tools v0.38.0 // indirect
	golang.zx2c4.com/wintun v0.0.0-20230126152724-0fa3db229ce2 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20250908214217-97024824d090 // indirect
)
