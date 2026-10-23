module github.com/Asutorufa/yuhaiin

go 1.27.2

replace (
	golang.zx2c4.com/wintun => github.com/yuhaiin/wintun v0.0.0-20240224105357-b28a4c71608e
	tailscale.com => github.com/Asutorufa/tailscale v0.0.0-20261016051747-4441c394b330
)

require (
	codeberg.org/miekg/dns v0.6.119
	github.com/amnezia-vpn/amneziawg-go/v3 v3.1.20260828
	github.com/apernet/quic-go v0.63.1-0.20261004180939-a10df75c260c
	github.com/coder/websocket v1.8.15
	github.com/godbus/dbus/v5 v5.2.4
	github.com/google/nftables v0.3.0
	github.com/google/pprof v0.0.0-20261016150608-1facf8f91b50
	github.com/libp2p/go-yamux/v5 v5.1.0
	github.com/mattn/go-sqlite3 v1.14.52
	github.com/oschwald/maxminddb-golang/v2 v2.8.0
	github.com/pires/go-proxyproto v0.16.0
	github.com/prometheus/client_golang v1.25.0
	github.com/refraction-networking/utls v1.8.2
	github.com/rhnvrm/simples3 v0.11.1
	github.com/slackhq/nebula v1.11.2
	github.com/tailscale/wireguard-go v0.0.0-20261002162406-18e99eba5393
	github.com/vishvananda/netlink v1.3.1
	github.com/vishvananda/netns v0.0.5
	github.com/xtls/reality v0.0.0-20261014101318-83f621788ca8
	github.com/yuhaiin/tailscale-lite v0.0.0-20261023094738-98b4de014876
	github.com/yuhaiin/yuhaiin.github.io v0.0.0-20261022032805-df51b667f746
	github.com/yuhaiin/zerotier-go v0.0.0-20261019131011-17140b61ce29
	go.uber.org/goleak v1.3.0
	golang.org/x/crypto v0.58.0
	golang.org/x/exp v0.0.0-20261014143641-f0251eb4aa3e
	golang.org/x/mobile v0.0.0-20261011034528-197770444867
	golang.org/x/mod v0.42.0
	golang.org/x/net v0.61.0
	golang.org/x/oauth2 v0.37.0
	golang.org/x/sync v0.24.0
	golang.org/x/sys v0.49.0
	golang.org/x/text v0.43.0
	golang.org/x/time v0.16.0
	golang.zx2c4.com/wireguard/windows v1.1.1
	gvisor.dev/gvisor v0.0.0-20260915211658-a6f909f08a72
	modernc.org/sqlite v1.61.0
	tailscale.com v1.9999999999.99999999999
)

require (
	dario.cat/mergo v1.0.2 // indirect
	filippo.io/bigmod v0.1.0 // indirect
	filippo.io/edwards25519 v1.2.0 // indirect
	github.com/DefinedNet/netlink v1.3.2-dn.1 // indirect
	github.com/akutz/memconn v0.1.0 // indirect
	github.com/andybalholm/brotli v1.2.3 // indirect
	github.com/anmitsu/go-shlex v0.0.0-20200514113438-38f4b401e2be // indirect
	github.com/armon/go-radix v1.0.0 // indirect
	github.com/axiomhq/hyperloglog v0.2.6 // indirect
	github.com/benbjohnson/immutable v0.4.3 // indirect
	github.com/beorn7/perks v1.0.1 // indirect
	github.com/bradfitz/reco v0.0.0-20260929154613-b883fbd17e3f // indirect
	github.com/cespare/xxhash/v2 v2.3.0 // indirect
	github.com/creachadair/msync v0.10.1 // indirect
	github.com/dblohm7/wingoes v0.0.0-20260526185140-fb298caac7ca // indirect
	github.com/dgryski/go-metro v0.0.0-20250106013310-edb8663e5e33 // indirect
	github.com/dustin/go-humanize v1.1.0 // indirect
	github.com/ebitengine/purego v0.10.2 // indirect
	github.com/flynn/noise v1.1.0 // indirect
	github.com/fxamacker/cbor/v2 v2.9.3 // indirect
	github.com/gaissmai/bart v0.29.0 // indirect
	github.com/go-json-experiment/json v0.0.0-20260820222146-c27c302e5fc3 // indirect
	github.com/go4org/hashtriemap v0.0.0-20260925222741-44e5305f85d9 // indirect
	github.com/gogo/protobuf v1.3.2 // indirect
	github.com/golang/groupcache v0.0.0-20241129210726-2c02b8208cf8 // indirect
	github.com/google/btree v1.1.3 // indirect
	github.com/google/go-cmp v0.7.0 // indirect
	github.com/google/gopacket v1.1.19 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/hdevalence/ed25519consensus v0.2.0 // indirect
	github.com/ianlancetaylor/demangle v0.0.0-20250417193237-f615e6bd150b // indirect
	github.com/jsimonetti/rtnetlink v1.4.2 // indirect
	github.com/juju/ratelimit v1.0.2 // indirect
	github.com/kamstrup/intmap v0.5.2 // indirect
	github.com/klauspost/compress v1.20.1 // indirect
	github.com/libp2p/go-buffer-pool v0.1.0 // indirect
	github.com/mattn/go-isatty v0.0.24 // indirect
	github.com/mdlayher/netlink v1.11.2 // indirect
	github.com/mdlayher/socket v0.7.0 // indirect
	github.com/miekg/dns v1.1.73 // indirect
	github.com/miekg/pkcs11 v1.1.2 // indirect
	github.com/mitchellh/go-ps v1.0.0 // indirect
	github.com/munnerz/goautoneg v0.0.0-20191010083416-a7dc8b61c822 // indirect
	github.com/nbrownus/go-metrics-prometheus v0.0.0-20210712211119-974a6260965f // indirect
	github.com/ncruces/go-strftime v1.1.0 // indirect
	github.com/prometheus/client_model v0.6.3 // indirect
	github.com/prometheus/common v0.72.0 // indirect
	github.com/prometheus/procfs v0.22.0 // indirect
	github.com/quic-go/qpack v0.6.0 // indirect
	github.com/rcrowley/go-metrics v0.0.0-20201227073835-cf1acfcdf475 // indirect
	github.com/remyoudompheng/bigfft v0.0.0-20230129092748-24d4a6f8daec // indirect
	github.com/stefanberger/go-pkcs11uri v0.0.0-20230803200340-78284954bff6 // indirect
	github.com/tailscale/certstore v0.1.1-0.20260409135935-3638fb84b77d // indirect
	github.com/tailscale/go-winio v0.0.0-20231025203758-c4f33415bf55 // indirect
	github.com/x448/float16 v0.8.4 // indirect
	go.uber.org/mock v0.6.0 // indirect
	go.yaml.in/yaml/v3 v3.0.5 // indirect
	go4.org/mem v0.0.0-20240501181205-ae6ca9944745 // indirect
	go4.org/netipx v0.0.0-20260823151212-3075585bcbeb // indirect
	golang.org/x/term v0.47.0 // indirect
	golang.org/x/tools v0.52.0 // indirect
	golang.zx2c4.com/wintun v0.0.0-20230126152724-0fa3db229ce2 // indirect
	golang.zx2c4.com/wireguard v0.0.0-20260522210424-ecfc5a8d5446 // indirect
	google.golang.org/protobuf v1.36.12 // indirect
	modernc.org/libc v1.79.0 // indirect
	modernc.org/mathutil v1.7.1 // indirect
	modernc.org/memory v1.12.1 // indirect
)
