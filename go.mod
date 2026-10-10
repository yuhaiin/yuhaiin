module github.com/Asutorufa/yuhaiin

go 1.27.1

replace (
	github.com/apernet/hysteria/core/v2 => github.com/Asutorufa/hysteria/core/v2 v2.13.1-0.20261007150228-a38075fd0e66
	github.com/prometheus-community/pro-bing => github.com/Asutorufa/pro-bing v0.0.0-20250716081333-626d07c0d4ca
	golang.zx2c4.com/wintun => github.com/yuhaiin/wintun v0.0.0-20240224105357-b28a4c71608e
	tailscale.com => github.com/Asutorufa/tailscale v0.0.0-20261004051059-f377f7ca3dbc
)

require (
	codeberg.org/miekg/dns v0.6.118
	github.com/apernet/hysteria/core/v2 v2.13.0
	github.com/apernet/hysteria/extras/v2 v2.13.0
	github.com/apernet/quic-go v0.63.1-0.20261004180939-a10df75c260c
	github.com/cilium/ebpf v0.22.0
	github.com/cloudflare/circl v1.6.5
	github.com/cockroachdb/pebble/v2 v2.1.7
	github.com/godbus/dbus/v5 v5.2.2
	github.com/google/nftables v0.3.0
	github.com/libp2p/go-yamux/v5 v5.1.0
	github.com/mattn/go-sqlite3 v1.14.52
	github.com/oschwald/maxminddb-golang/v2 v2.7.0
	github.com/pires/go-proxyproto v0.15.0
	github.com/prometheus-community/pro-bing v0.9.1
	github.com/prometheus/client_golang v1.25.0
	github.com/quic-go/connect-ip-go v0.4.0
	github.com/quic-go/quic-go v0.63.0
	github.com/refraction-networking/utls v1.8.2
	github.com/rhnvrm/simples3 v0.11.1
	github.com/tailscale/wireguard-go v0.0.0-20261002162406-18e99eba5393
	github.com/vishvananda/netlink v1.3.1
	github.com/vishvananda/netns v0.0.5
	github.com/xtls/reality v0.0.0-20260921001439-3c98159dee38
	github.com/yuhaiin/yuhaiin.github.io v0.0.0-20261009035247-d5be68ea987b
	golang.org/x/crypto v0.58.0
	golang.org/x/mobile v0.0.0-20260908204917-8b95e45f8d3e
	golang.org/x/mod v0.42.0
	golang.org/x/net v0.61.0
	golang.org/x/sync v0.24.0
	golang.org/x/sys v0.49.0
	golang.org/x/time v0.16.0
	golang.zx2c4.com/wireguard/windows v1.1.1
	google.golang.org/protobuf v1.36.12
	gvisor.dev/gvisor v0.0.0-20260915211658-a6f909f08a72
	modernc.org/sqlite v1.60.1
	tailscale.com v1.9999999999.99999999999
)

require (
	filippo.io/edwards25519 v1.2.0 // indirect
	github.com/DataDog/zstd v1.5.7 // indirect
	github.com/RaduBerinde/axisds v0.1.0 // indirect
	github.com/RaduBerinde/btreemap v0.0.0-20260105202824-d3184786f603 // indirect
	github.com/akutz/memconn v0.1.0 // indirect
	github.com/alexbrainman/sspi v0.0.0-20250919150558-7d374ff0d59e // indirect
	github.com/andybalholm/brotli v1.2.3 // indirect
	github.com/beorn7/perks v1.0.1 // indirect
	github.com/cespare/xxhash/v2 v2.3.0 // indirect
	github.com/cockroachdb/crlib v0.0.0-20251122031428-fe658a2dbda1 // indirect
	github.com/cockroachdb/errors v1.13.0 // indirect
	github.com/cockroachdb/logtags v0.0.0-20241215232642-bb51bb14a506 // indirect
	github.com/cockroachdb/redact v1.1.8 // indirect
	github.com/cockroachdb/swiss v0.0.0-20260820225851-333444432258 // indirect
	github.com/cockroachdb/tokenbucket v0.0.0-20250429170803-42689b6311bb // indirect
	github.com/coder/websocket v1.8.15 // indirect
	github.com/creachadair/msync v0.10.1 // indirect
	github.com/dblohm7/wingoes v0.0.0-20260526185140-fb298caac7ca // indirect
	github.com/dunglas/httpsfv v1.1.1 // indirect
	github.com/dustin/go-humanize v1.0.1 // indirect
	github.com/fxamacker/cbor/v2 v2.9.3 // indirect
	github.com/gaissmai/bart v0.29.0 // indirect
	github.com/getsentry/sentry-go v0.47.0 // indirect
	github.com/go-json-experiment/json v0.0.0-20260820222146-c27c302e5fc3 // indirect
	github.com/gogo/protobuf v1.3.2 // indirect
	github.com/golang/groupcache v0.0.0-20241129210726-2c02b8208cf8 // indirect
	github.com/golang/snappy v1.0.0 // indirect
	github.com/google/btree v1.1.3 // indirect
	github.com/google/go-cmp v0.7.0 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/hdevalence/ed25519consensus v0.2.0 // indirect
	github.com/huin/goupnp v1.3.0 // indirect
	github.com/jsimonetti/rtnetlink v1.4.2 // indirect
	github.com/juju/ratelimit v1.0.2 // indirect
	github.com/klauspost/compress v1.20.1 // indirect
	github.com/kr/pretty v0.3.1 // indirect
	github.com/kr/text v0.2.0 // indirect
	github.com/libp2p/go-buffer-pool v0.1.0 // indirect
	github.com/mattn/go-isatty v0.0.24 // indirect
	github.com/mdlayher/netlink v1.11.2 // indirect
	github.com/mdlayher/socket v0.7.0 // indirect
	github.com/minio/minlz v1.1.1 // indirect
	github.com/mitchellh/go-ps v1.0.0 // indirect
	github.com/munnerz/goautoneg v0.0.0-20191010083416-a7dc8b61c822 // indirect
	github.com/ncruces/go-strftime v1.0.0 // indirect
	github.com/pkg/errors v0.9.1 // indirect
	github.com/prometheus/client_model v0.6.3 // indirect
	github.com/prometheus/common v0.72.0 // indirect
	github.com/prometheus/procfs v0.22.0 // indirect
	github.com/quic-go/qpack v0.6.0 // indirect
	github.com/remyoudompheng/bigfft v0.0.0-20230129092748-24d4a6f8daec // indirect
	github.com/rogpeppe/go-internal v1.16.0 // indirect
	github.com/safchain/ethtool v0.7.0 // indirect
	github.com/stretchr/objx v0.5.3 // indirect
	github.com/stretchr/testify v1.12.1 // indirect
	github.com/tailscale/certstore v0.1.1-0.20260409135935-3638fb84b77d // indirect
	github.com/tailscale/go-winio v0.0.0-20231025203758-c4f33415bf55 // indirect
	github.com/tailscale/hujson v0.0.0-20260727124030-b80ff77dac4f // indirect
	github.com/tailscale/peercred v0.0.0-20250107143737-35a0c7bd7edc // indirect
	github.com/tailscale/web-client-prebuilt v0.0.0-20260917222731-e0ed2d0d0fea // indirect
	github.com/x448/float16 v0.8.4 // indirect
	github.com/yosida95/uritemplate/v3 v3.0.2 // indirect
	go.uber.org/mock v0.6.0 // indirect
	go.yaml.in/yaml/v3 v3.0.5 // indirect
	go4.org/mem v0.0.0-20240501181205-ae6ca9944745 // indirect
	go4.org/netipx v0.0.0-20260823151212-3075585bcbeb // indirect
	golang.org/x/exp v0.0.0-20260908205506-85c1c2202aba // indirect
	golang.org/x/oauth2 v0.37.0 // indirect
	golang.org/x/term v0.47.0 // indirect
	golang.org/x/text v0.43.0 // indirect
	golang.org/x/tools v0.51.0 // indirect
	golang.zx2c4.com/wintun v0.0.0-20230126152724-0fa3db229ce2 // indirect
	modernc.org/libc v1.77.1 // indirect
	modernc.org/mathutil v1.7.1 // indirect
	modernc.org/memory v1.12.1 // indirect
)

tool github.com/cilium/ebpf/cmd/bpf2go
