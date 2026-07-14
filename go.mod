module github.com/Asutorufa/yuhaiin

go 1.26.4

replace (
	github.com/prometheus-community/pro-bing => github.com/Asutorufa/pro-bing v0.0.0-20250716081333-626d07c0d4ca
	github.com/tailscale/wireguard-go => github.com/yuhaiin/wireguard-go v0.0.0-20260617053048-09509f5a86ad
	golang.zx2c4.com/wintun => github.com/yuhaiin/wintun v0.0.0-20240224105357-b28a4c71608e
	tailscale.com => github.com/Asutorufa/tailscale v0.0.0-20260617052153-1a2972bf0399
)

require (
	github.com/cilium/ebpf v0.22.0
	github.com/cloudflare/circl v1.6.4
	github.com/cockroachdb/pebble/v2 v2.1.6
	github.com/godbus/dbus/v5 v5.2.2
	github.com/google/nftables v0.3.0
	github.com/grafana/pyroscope-go/godeltaprof v0.1.12
	github.com/libp2p/go-yamux/v5 v5.1.0
	codeberg.org/miekg/dns v0.6.84
	github.com/ncruces/go-sqlite3 v0.35.2
	github.com/oschwald/maxminddb-golang/v2 v2.4.1
	github.com/pires/go-proxyproto v0.15.0
	github.com/prometheus-community/pro-bing v0.9.1
	github.com/prometheus/client_golang v1.23.2
	github.com/quic-go/connect-ip-go v0.1.0
	github.com/quic-go/quic-go v0.60.0
	github.com/refraction-networking/utls v1.8.2
	github.com/rhnvrm/simples3 v0.11.1
	github.com/tailscale/wireguard-go v0.0.0-20260611001507-ffb138071028
	github.com/vishvananda/netlink v1.3.1
	github.com/xtls/reality v0.0.0-20260322125925-9234c772ba8f
	github.com/yuhaiin/yuhaiin.github.io v0.0.0-20260711161803-3827c9cf8294
	golang.org/x/crypto v0.54.0
	golang.org/x/mobile v0.0.0-20260709172247-6129f5bee9d5
	golang.org/x/mod v0.38.0
	golang.org/x/net v0.57.0
	golang.org/x/sync v0.22.0
	golang.org/x/sys v0.47.0
	golang.org/x/time v0.15.0
	golang.zx2c4.com/wireguard/windows v1.0.1
	google.golang.org/protobuf v1.36.11
	gvisor.dev/gvisor v0.0.0-20260224225140-573d5e7127a8
	tailscale.com v1.9999999999.99999999999
)

require (
	filippo.io/edwards25519 v1.2.0 // indirect
	github.com/DataDog/zstd v1.5.7 // indirect
	github.com/RaduBerinde/axisds v0.1.0 // indirect
	github.com/RaduBerinde/btreemap v0.0.0-20260105202824-d3184786f603 // indirect
	github.com/akutz/memconn v0.1.0 // indirect
	github.com/alexbrainman/sspi v0.0.0-20250919150558-7d374ff0d59e // indirect
	github.com/andybalholm/brotli v1.2.1 // indirect
	github.com/aws/aws-sdk-go-v2 v1.42.0 // indirect
	github.com/aws/aws-sdk-go-v2/config v1.32.25 // indirect
	github.com/aws/smithy-go v1.27.2 // indirect
	github.com/beorn7/perks v1.0.1 // indirect
	github.com/cespare/xxhash/v2 v2.3.0 // indirect
	github.com/cockroachdb/crlib v0.0.0-20251122031428-fe658a2dbda1 // indirect
	github.com/cockroachdb/errors v1.13.0 // indirect
	github.com/cockroachdb/logtags v0.0.0-20241215232642-bb51bb14a506 // indirect
	github.com/cockroachdb/redact v1.1.8 // indirect
	github.com/cockroachdb/swiss v0.0.0-20251224182025-b0f6560f979b // indirect
	github.com/cockroachdb/tokenbucket v0.0.0-20250429170803-42689b6311bb // indirect
	github.com/coder/websocket v1.8.15 // indirect
	github.com/creachadair/msync v0.9.0 // indirect
	github.com/dblohm7/wingoes v0.0.0-20260526185140-fb298caac7ca // indirect
	github.com/dunglas/httpsfv v1.1.0 // indirect
	github.com/fxamacker/cbor/v2 v2.9.2 // indirect
	github.com/gaissmai/bart v0.28.0 // indirect
	github.com/getsentry/sentry-go v0.47.0 // indirect
	github.com/go-json-experiment/json v0.0.0-20260601182631-00ed12fed2a6 // indirect
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
	github.com/klauspost/compress v1.18.6 // indirect
	github.com/kr/pretty v0.3.1 // indirect
	github.com/kr/text v0.2.0 // indirect
	github.com/libp2p/go-buffer-pool v0.1.0 // indirect
	github.com/mdlayher/netlink v1.11.2 // indirect
	github.com/mdlayher/socket v0.6.1 // indirect
	github.com/minio/minlz v1.1.1 // indirect
	github.com/mitchellh/go-ps v1.0.0 // indirect
	github.com/munnerz/goautoneg v0.0.0-20191010083416-a7dc8b61c822 // indirect
	github.com/ncruces/go-sqlite3-wasm/v3 v3.2.35303 // indirect
	github.com/ncruces/julianday v1.0.0 // indirect
	github.com/pkg/errors v0.9.1 // indirect
	github.com/prometheus/client_model v0.6.2 // indirect
	github.com/prometheus/common v0.68.1 // indirect
	github.com/prometheus/procfs v0.20.1 // indirect
	github.com/quic-go/qpack v0.6.0 // indirect
	github.com/rogpeppe/go-internal v1.15.0 // indirect
	github.com/safchain/ethtool v0.7.0 // indirect
	github.com/tailscale/certstore v0.1.1-0.20260409135935-3638fb84b77d // indirect
	github.com/tailscale/go-winio v0.0.0-20231025203758-c4f33415bf55 // indirect
	github.com/tailscale/hujson v0.0.0-20260302212456-ecc657c15afd // indirect
	github.com/tailscale/peercred v0.0.0-20250107143737-35a0c7bd7edc // indirect
	github.com/tailscale/web-client-prebuilt v0.0.0-20251127225136-f19339b67368 // indirect
	github.com/vishvananda/netns v0.0.5 // indirect
	github.com/x448/float16 v0.8.4 // indirect
	github.com/yosida95/uritemplate/v3 v3.0.2 // indirect
	go.uber.org/mock v0.6.0 // indirect
	go4.org/mem v0.0.0-20240501181205-ae6ca9944745 // indirect
	go4.org/netipx v0.0.0-20231129151722-fdeea329fbba // indirect
	golang.org/x/exp v0.0.0-20260611194520-c48552f49976 // indirect
	golang.org/x/oauth2 v0.36.0 // indirect
	golang.org/x/term v0.45.0 // indirect
	golang.org/x/text v0.40.0 // indirect
	golang.org/x/tools v0.48.0 // indirect
	golang.zx2c4.com/wintun v0.0.0-20230126152724-0fa3db229ce2 // indirect
)

tool github.com/cilium/ebpf/cmd/bpf2go
