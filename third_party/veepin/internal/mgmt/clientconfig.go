package mgmt

// Client-config generation: given a listener's on-disk config, produce a client
// connection profile (profile.Config — the exact shape `veepin connect <name>`
// dials) plus any companion files the profile references by path. Secrets come
// from the store, not from the redacted API reads, so a generated profile is
// complete and contains no "<redacted>" placeholder.
//
// The derivation is protocol-aware only where it must be:
//
//   - Most protocols are a straight mapping: the operator's endpoint becomes
//     the client's server/gateway/remote, and the listener's own options carry
//     over (psk, user, password, group identity) unchanged.
//   - L2TPv3 is symmetric, so session/cookie ids swap ends.
//   - WireGuard and AmneziaWG need real provisioning: a fresh client keypair, a
//     free address from the server's subnet, and the peer added to the running
//     server (the peers JSON option) followed by a cold rebuild. Only those two
//     mutate the listener; everything else is pure assembly.
//
// A file-path client option (ca, cert, key, tls-auth, ...) is bundled: its
// server-side file is read into the response and the option rewritten to the
// file's base name, so the operator places the companion next to the profile.

import (
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"maps"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/xen0bit/veepin/client"
	"github.com/xen0bit/veepin/internal/keygen"
	"github.com/xen0bit/veepin/internal/profile"
	"github.com/xen0bit/veepin/internal/supervisor"
	"github.com/xen0bit/veepin/wireguard"
)

// ClientConfigRequest is the operator input to POST /api/listeners/{name}/client-config.
type ClientConfigRequest struct {
	// Name is the profile name to embed; defaults to the listener name.
	Name string `json:"name,omitempty"`
	// Endpoint is the address clients dial — the server's publicly-reachable
	// host[:port]. The supervisor cannot know its own public hostname, so this
	// is required for every protocol whose client config carries a server
	// address (all but nebula).
	Endpoint string `json:"endpoint,omitempty"`
	// Overrides are additional client options (validated against the protocol's
	// client OptSpec), e.g. a client identity or hub name.
	Overrides map[string]string `json:"overrides,omitempty"`
}

// endpointCoverageWarnings reports that the listener's own server certificate
// does not cover the address the operator says clients will dial.
//
// The two facts arrive from different places and nothing used to compare them:
// the certificate's SANs are fixed when the listener is created (from its
// hostnames field, or the loopback defaults), and the endpoint is supplied here,
// possibly months later by someone else. When they disagree the profile is
// perfectly well-formed and every connection made with it fails name
// verification -- which reads as a certificate problem long after the moment
// anyone could connect it to a form field they left empty.
//
// A warning, not an error: an operator who intends to pin the certificate, or
// to dial with verification off, is doing something legitimate.
func endpointCoverageWarnings(serverOpts map[string]string, endpoint string) []string {
	certPath := serverOpts["cert"]
	if endpoint == "" || certPath == "" {
		return nil
	}
	host := endpoint
	if h, _, err := net.SplitHostPort(endpoint); err == nil {
		host = h
	}
	body, err := os.ReadFile(certPath)
	if err != nil {
		// Unreadable here is already reported by the bundler where it bundles,
		// and is not this check's news to break.
		return nil
	}
	block, _ := pem.Decode(body)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil
	}
	if cert.VerifyHostname(host) == nil {
		return nil
	}
	names := slices.Clone(cert.DNSNames)
	for _, ip := range cert.IPAddresses {
		names = append(names, ip.String())
	}
	covers := "nothing"
	if len(names) > 0 {
		covers = strings.Join(names, ", ")
	}
	return []string{fmt.Sprintf(
		"the server certificate does not cover %q (it covers %s); clients will fail name verification "+
			"unless the listener's hostnames include it and the key material is regenerated",
		host, covers)}
}

// clientConfigFile is one companion file bundled with a generated profile.
type clientConfigFile struct {
	Name    string `json:"name"`
	Content string `json:"content"`
}

// clientConfigResponse is the body of a successful generation.
type clientConfigResponse struct {
	Protocol string             `json:"protocol"`
	Profile  profile.Config     `json:"profile"`
	Files    []clientConfigFile `json:"files,omitempty"`
	// Warnings names the companion files that could not be bundled. The profile
	// is still usable; those options still point at the server's own paths and
	// the operator has to place the files themselves.
	Warnings []string `json:"warnings,omitempty"`
	// PeersAdded reports how many peers were provisioned onto the listener
	// (1 for WireGuard-family generation, 0 for pure assembly).
	PeersAdded int `json:"peers_added,omitempty"`
}

// clientPortKey is the option every derived protocol's client uses for the
// server port. It is a constant rather than a per-row field because all of them
// spell it the same; TestEveryDerivedProtocolDeclaresThePortOption proves that
// against the registry instead of the table restating it fourteen times, and
// fails by name the day a protocol disagrees.
const clientPortKey = "port"

// clientProtoMap describes how one protocol's client config derives from its
// listener's server options. The string keys are the Opt* values the facades
// declare; TestClientConfigMapKeysAreDeclared ties every one to the registry's
// OptSpecs so the two cannot drift.
type clientProtoMap struct {
	// endpointKey is the client option the operator's Endpoint host fills.
	// Empty means the protocol's client config has no single server address
	// (nebula), and an Endpoint is then refused rather than silently dropped.
	endpointKey string
	// serverPort is the listener option key holding the listen port ("" when
	// the protocol binds a fixed port the client already defaults to).
	serverPort string
	// clientDefaultPort is the port the client dials on its own. A derived port
	// equal to it is left out, so a profile for a stock deployment stays short.
	clientDefaultPort string
	// carry maps a client option key to the server option key whose value moves
	// across unchanged (psk, user, password, group identity).
	carry map[string]string
}

// clientProtoMaps is the per-protocol derivation table. Only the WireGuard
// family is absent, because it is provisioned rather than assembled.
var clientProtoMaps = map[string]clientProtoMap{
	"ikev2": {
		endpointKey: "gateway", clientDefaultPort: "500",
		// No dns carry: the ikev2 client takes its DNS from the server's
		// config-mode assignment, and its connect flags accept no -dns.
		carry: map[string]string{"psk": "psk", "server-id": "id"},
	},
	"openvpn": {
		endpointKey: "remote", serverPort: "port", clientDefaultPort: "1194",
		// The client verifies the server with the CA that signed it — the same
		// ca.crt the server holds, so it carries over and is bundled.
		carry: map[string]string{"ca": "ca"},
	},
	"sstp": {
		endpointKey: "server", serverPort: "port", clientDefaultPort: "443",
		carry: map[string]string{"user": "user", "password": "password"},
	},
	"l2tp": {
		endpointKey: "server", serverPort: "port", clientDefaultPort: "500",
		carry: map[string]string{"psk": "psk", "user": "user", "password": "password", "dns": "dns"},
	},
	"anyconnect": {
		endpointKey: "server", serverPort: "port", clientDefaultPort: "443",
		carry: map[string]string{"user": "user", "password": "password"},
	},
	"fortinet": {
		endpointKey: "server", serverPort: "port", clientDefaultPort: "443",
		// The server's own cert doubles as a client-side pin: bundling it as the
		// client's CA bundle verifies this server without -insecure.
		carry: map[string]string{"user": "user", "password": "pass", "ca": "cert"},
	},
	"cisco": {
		endpointKey: "server", serverPort: "port", clientDefaultPort: "500",
		carry: map[string]string{"group": "group", "group-psk": "group-psk", "user": "user", "password": "pass"},
	},
	"pulse": {
		endpointKey: "server", serverPort: "port", clientDefaultPort: "443",
		carry: map[string]string{"user": "user", "password": "pass", "ca": "cert"},
	},
	"gp": {
		endpointKey: "server", serverPort: "port", clientDefaultPort: "443",
		carry: map[string]string{"user": "user", "password": "pass", "ca": "cert"},
	},
	"masque": {
		endpointKey: "server", serverPort: "port", clientDefaultPort: "443",
		carry: map[string]string{"ca": "cert"},
	},
	"ssh": {
		endpointKey: "server", serverPort: "port", clientDefaultPort: "22",
		carry: map[string]string{"user": "user", "password": "password"},
	},
	"softether": {
		endpointKey: "server", serverPort: "port", clientDefaultPort: "443",
		carry: map[string]string{"user": "user", "password": "pass"},
	},
	"toy": {
		endpointKey: "server", serverPort: "port", clientDefaultPort: "5555",
		carry: map[string]string{"user": "user", "secret": "secret"},
	},
	"l2tpv3": {
		endpointKey: "gateway", serverPort: "port", clientDefaultPort: "1701",
		// A static pseudowire has no control plane to negotiate over, so the
		// two ends are mirror images: what the server calls its own session id,
		// cookie and CCID is what the client must send TO, and vice versa. The
		// swap is in buildClientConfig; carry brings across the settings both
		// ends must simply agree on.
		carry: map[string]string{"sublayer": "sublayer", "shape": "shape", "keepalive": "keepalive"},
	},
	// nebula has no endpoint: a host is reached at the underlay address its
	// lighthouse publishes, not at one the operator names here. Only the CA
	// carries over (and is bundled) -- the mesh's trust root is the one thing
	// every host shares. cert and key deliberately do NOT: they are this
	// lighthouse's own identity, and handing them to a client would clone the
	// lighthouse rather than provision a peer. Each host needs a certificate
	// the CA signed for its own overlay address, which is an issuance step
	// veepin does not perform; the operator supplies cert, key and lighthouses
	// as overrides, and the required-option check below names them.
	"nebula": {
		carry: map[string]string{"ca": "ca", "cipher": "cipher", "mtu": "mtu"},
	},
}

// handleClientConfig is POST /api/listeners/{name}/client-config. It assembles
// the profile from the on-disk listener config and the operator's inputs; for
// WireGuard-family protocols it also provisions a peer and cold-rebuilds the
// listener, which is why this is a POST and not a GET.
func (s *Server) handleClientConfig(w http.ResponseWriter, r *http.Request) {
	name := s.pathName(w, r)
	if name == "" {
		return
	}
	// Body first, then the lock: see handleCreateListener.
	var req ClientConfigRequest
	if err := decodeJSON(r, &req); err != nil {
		s.audit.record("listener.client-config", name, err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	// Held even for the assembly-only protocols: they read the listener file,
	// and the WireGuard path behind the same handler rewrites it.
	s.mutate.Lock()
	defer s.mutate.Unlock()
	var res error
	defer func() { s.audit.record("listener.client-config", name, res) }()

	cfg, err := supervisor.ParseListenerFile(supervisor.ListenerPath(s.dir, name))
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			res = err
			http.Error(w, "no such listener", http.StatusNotFound)
			return
		}
		res = err
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	out, err := s.buildClientConfig(cfg, req)
	if err != nil {
		res = err
		// Most derivation failures are the operator's input; the rest are ours.
		// Which is which was decided by strings.HasPrefix over the error text,
		// so every genuine server fault on the WireGuard path -- an entropy
		// failure, an exhausted subnet, a key that will not derive -- was
		// reported as 400 Bad Request, telling the operator their request was
		// malformed when it was not.
		http.Error(w, err.Error(), statusForBuildError(err))
		return
	}
	writeJSON(w, http.StatusOK, out)
}

// errServerFault marks a client-config failure that is ours rather than the
// caller's: exhausted entropy, an exhausted address pool, a listener whose
// stored key will not derive, a rebuild that would not come back. Joined with
// errors.Is rather than matched on message text, so rewording an error cannot
// silently change the status code it produces.
var errServerFault = errors.New("mgmt: server fault")

// serverFault wraps err so statusForBuildError answers 500 for it.
func serverFault(format string, args ...any) error {
	return fmt.Errorf("%w: %s", errServerFault, fmt.Sprintf(format, args...))
}

// statusForBuildError maps a buildClientConfig error to its HTTP status.
func statusForBuildError(err error) int {
	if errors.Is(err, errServerFault) {
		return http.StatusInternalServerError
	}
	return http.StatusBadRequest
}

// buildClientConfig derives a client profile for the listener. It is the
// protocol-agnostic core plus the two special cases that need real work.
func (s *Server) buildClientConfig(cfg supervisor.ListenerConfig, req ClientConfigRequest) (*clientConfigResponse, error) {
	if !knownClientProtocol(cfg.Protocol) {
		return nil, fmt.Errorf("mgmt: %s cannot run as a client", cfg.Protocol)
	}
	if cfg.Protocol == "wireguard" || cfg.Protocol == "amneziawg" {
		return s.buildWGClientConfig(cfg, req)
	}
	m, ok := clientProtoMaps[cfg.Protocol]
	if !ok {
		return nil, fmt.Errorf("mgmt: no client-config derivation for %s", cfg.Protocol)
	}
	if err := validateOverrides(cfg.Protocol, req.Overrides); err != nil {
		return nil, err
	}

	opts := map[string]string{}
	if m.endpointKey == "" {
		// Refused rather than ignored: an operator who names an endpoint for a
		// protocol that has none has misunderstood something, and silently
		// dropping it would hand back a profile that looks right and is not.
		if req.Endpoint != "" {
			return nil, fmt.Errorf("mgmt: %s clients take no server address; leave endpoint empty", cfg.Protocol)
		}
	} else {
		if req.Endpoint == "" {
			return nil, errors.New("mgmt: endpoint is required (the address clients dial)")
		}
		// Host and port go into SEPARATE options. Every client here dials
		// net.JoinHostPort(<endpointKey>, <port>), so folding the port into the
		// host produces "vpn.example.com:1195:1194" and a "too many colons"
		// resolve failure. The WireGuard family is the exception -- its
		// endpoint option genuinely is host:port -- which is why that path uses
		// withPortRequired instead.
		host, port := splitEndpoint(req.Endpoint, cfg.Options[m.serverPort], m.clientDefaultPort)
		opts[m.endpointKey] = host
		if port != "" && port != m.clientDefaultPort {
			opts[clientPortKey] = port
		}
	}
	// derived records which option values the listener's own config produced.
	// Only those are ever opened from disk; see bundleClientConfig.
	derived := map[string]bool{}
	for ck, sk := range m.carry {
		if v := cfg.Options[sk]; v != "" {
			opts[ck] = v
			derived[ck] = true
		}
	}
	// L2TPv3 is symmetric: the client's session/cookie/CCID are the server's
	// peer-side ones, and vice versa. Only non-empty values are written so an
	// unset CCID pair does not become a literal "" the client then parses.
	if cfg.Protocol == "l2tpv3" {
		for ours, theirs := range map[string]string{
			"session-id": "peer-session-id",
			"cookie":     "peer-cookie",
			"ccid":       "peer-ccid",
		} {
			if v := cfg.Options[theirs]; v != "" {
				opts[ours] = v
			}
			if v := cfg.Options[ours]; v != "" {
				opts[theirs] = v
			}
		}
	}
	applyOverrides(opts, derived, req.Overrides)

	return s.bundleClientConfig(cfg, req, opts, derived, 0)
}

// applyOverrides layers the operator's values over the derived ones and drops
// each overridden key from the derived set, so an override never inherits the
// trust the listener's own config carries.
func applyOverrides(opts map[string]string, derived map[string]bool, overrides map[string]string) {
	for k, v := range overrides {
		opts[k] = v
		delete(derived, k)
	}
}

// bundleClientConfig rewrites file-path options into bundled companions and
// assembles the response. Called by both the generic and the WireGuard path.
//
// Only paths the LISTENER's config supplied are opened. An operator-supplied
// override is a path the API would otherwise read and hand back verbatim, and
// the supervisor runs as root: with the value unchecked, anyone holding the
// bearer token could POST {"overrides":{"ca":"/etc/shadow"}} against any
// listener whose protocol declares a file-path option and read the file out of
// the response. Overridden paths are passed through into the profile untouched
// instead -- the operator named a file they already have.
func (s *Server) bundleClientConfig(cfg supervisor.ListenerConfig, req ClientConfigRequest, opts map[string]string, derived map[string]bool, peersAdded int) (*clientConfigResponse, error) {
	fileOpts := map[string]bool{}
	if specs, ok := client.ClientOptsFor(cfg.Protocol); ok {
		for _, sp := range specs {
			if sp.Kind == client.OptFilePath {
				fileOpts[sp.Key] = true
			}
		}
	}
	var files []clientConfigFile
	var warnings []string
	// Sorted so the bundle and its warnings are byte-identical across runs; map
	// order would otherwise reshuffle the files array on every call.
	for _, k := range slices.Sorted(maps.Keys(opts)) {
		v := opts[k]
		if !fileOpts[k] || v == "" || !derived[k] {
			continue
		}
		body, err := os.ReadFile(v)
		if err != nil {
			// Left pointing at the server's path, and said so: the previous
			// version swallowed this, so an unreadable CA produced a profile
			// referencing an absolute path on the server with no companion file
			// and nothing to tell the operator the bundle was incomplete.
			warnings = append(warnings, fmt.Sprintf("%s: %s not bundled: %v", k, v, err))
			continue
		}
		base := filepath.Base(v)
		opts[k] = base
		files = append(files, clientConfigFile{Name: base, Content: string(body)})
	}
	// Against the listener's own certificate, not against whatever was bundled:
	// OpenVPN ships the client the CA and not the leaf, so a check over the
	// bundle would silently cover nothing for the protocol most likely to need
	// it. What matters is the certificate this listener will present.
	warnings = append(warnings, endpointCoverageWarnings(cfg.Options, req.Endpoint)...)
	if err := requireDeclaredOptions(cfg.Protocol, opts); err != nil {
		return nil, err
	}
	pname := req.Name
	if pname == "" {
		pname = cfg.Name
	}
	return &clientConfigResponse{
		Protocol: cfg.Protocol,
		Profile: profile.Config{
			Name:     pname,
			Protocol: cfg.Protocol,
			Options:  opts,
		},
		Files:      files,
		Warnings:   warnings,
		PeersAdded: peersAdded,
	}, nil
}

// buildWGClientConfig is the WireGuard-family path: it mints a client keypair,
// allocates a free address from the server's subnet, provisions the peer onto
// the listener, cold-rebuilds it, and returns the client profile.
func (s *Server) buildWGClientConfig(cfg supervisor.ListenerConfig, req ClientConfigRequest) (*clientConfigResponse, error) {
	if err := validateOverrides(cfg.Protocol, req.Overrides); err != nil {
		return nil, err
	}
	if req.Endpoint == "" {
		return nil, errors.New("mgmt: endpoint is required (the address clients dial)")
	}
	serverAddr := cfg.Options[wireguard.OptServerAddress]
	if serverAddr == "" {
		return nil, errors.New("mgmt: the listener has no tunnel address; set 'address' on it first")
	}
	serverPub, err := serverPublicKey(cfg.Options[wireguard.OptServerPrivateKey], cfg.Options["public-key"])
	if err != nil {
		return nil, err
	}
	clientPriv, clientPub, err := keygen.WireGuardKeypair()
	if err != nil {
		return nil, serverFault("generating a client keypair: %v", err)
	}
	alloc, err := allocateWGAddress(serverAddr, usedWGAddresses(cfg.Options))
	if err != nil {
		return nil, serverFault("allocating a tunnel address: %v", err)
	}

	// Provision the peer: append it to the listener's peers JSON, persist, and
	// cold-rebuild so the new client is live before its config leaves the API.
	prevPeers := cfg.Options[wireguard.OptServerPeers]
	peers, err := parseWGPeers(prevPeers)
	if err != nil {
		return nil, err
	}
	peers = append(peers, wireguard.ServerPeer{
		PublicKey:  clientPub,
		AllowedIPs: []string{alloc.String()},
	})
	body, err := json.Marshal(peers)
	if err != nil {
		return nil, serverFault("serializing peers: %v", err)
	}
	cfg.Options[wireguard.OptServerPeers] = string(body)
	if err := supervisor.WriteListenerFile(s.dir, cfg); err != nil {
		return nil, serverFault("provisioning peer: %v", err)
	}
	if err := s.mgr.Rebuild(cfg.Name); err != nil {
		// Roll the peer back out. The client's private key exists only in this
		// response, which is about to become a 500, so leaving the peer on disk
		// would permanently consume a tunnel address for a key nobody holds and
		// make every later allocation skip it.
		if prevPeers == "" {
			delete(cfg.Options, wireguard.OptServerPeers)
		} else {
			cfg.Options[wireguard.OptServerPeers] = prevPeers
		}
		if rerr := supervisor.WriteListenerFile(s.dir, cfg); rerr != nil {
			s.log.Warnf("mgmt: %s: rolling back a failed peer provision: %v", cfg.Name, rerr)
		}
		return nil, serverFault("provisioning peer: %v", err)
	}

	opts := map[string]string{
		"private-key": clientPriv,
		"public-key":  serverPub,
		"endpoint":    withPortRequired(req.Endpoint, cfg.Options[wireguard.OptServerListenPort], "51820"),
		"address":     alloc.String(),
		"allowed-ips": "0.0.0.0/0",
	}
	// The obfuscation parameters are not negotiated: the client must be given
	// exactly what the server is running, so they carry across for AmneziaWG.
	for _, k := range []string{
		"type-init", "type-resp", "type-cookie", "type-trans",
		"pad-init", "pad-resp", "pad-cookie", "pad-trans",
		"junk-count", "junk-min", "junk-max",
	} {
		if v := cfg.Options[k]; v != "" && v != "0" {
			opts[k] = v
		}
	}
	// No file-path option is derived here -- the WireGuard family's key material
	// is inline, not on disk -- so nothing is bundled and derived stays empty.
	derived := map[string]bool{}
	applyOverrides(opts, derived, req.Overrides)
	return s.bundleClientConfig(cfg, req, opts, derived, 1)
}

// serverPublicKey recovers the server's public half: the stored generated value
// if present, otherwise derived from the server's private key.
func serverPublicKey(priv, stored string) (string, error) {
	if stored != "" {
		return stored, nil
	}
	if priv == "" {
		return "", errors.New("mgmt: the listener has no server key to derive the public key from")
	}
	pub, err := keygen.WireGuardPublicKey(priv)
	if err != nil {
		return "", serverFault("deriving the server public key: %v", err)
	}
	return pub, nil
}

// usedWGAddresses is the set of host addresses already claimed within the
// server's subnet: the server's own address plus every /32 in existing peers'
// allowed-ips. It is what makes the next allocation collision-free across
// generations.
func usedWGAddresses(opts map[string]string) map[netip.Addr]bool {
	used := map[netip.Addr]bool{}
	if a := opts[wireguard.OptServerAddress]; a != "" {
		if p, err := netip.ParsePrefix(a); err == nil {
			used[p.Addr()] = true
		}
	}
	for _, peer := range allWGPeers(opts) {
		for _, cidr := range peer.AllowedIPs {
			if p, err := netip.ParsePrefix(cidr); err == nil {
				used[p.Addr()] = true
			}
		}
	}
	return used
}

// allWGPeers is every configured peer across both the single-peer options and
// the peers JSON.
func allWGPeers(opts map[string]string) []wireguard.ServerPeer {
	var out []wireguard.ServerPeer
	if k := opts[wireguard.OptServerPeerPublicKey]; k != "" {
		out = append(out, wireguard.ServerPeer{PublicKey: k, AllowedIPs: wireguard.SplitList(opts[wireguard.OptServerPeerAllowedIPs])})
	}
	if v := opts[wireguard.OptServerPeers]; v != "" {
		if peers, err := parseWGPeers(v); err == nil {
			out = append(out, peers...)
		}
	}
	return out
}

// parseWGPeers decodes the peers JSON option.
func parseWGPeers(v string) ([]wireguard.ServerPeer, error) {
	if v == "" {
		return nil, nil
	}
	var out []wireguard.ServerPeer
	if err := json.Unmarshal([]byte(v), &out); err != nil {
		return nil, fmt.Errorf("mgmt: invalid peers JSON: %w", err)
	}
	return out, nil
}

// allocateWGAddress picks the lowest host in the server's subnet that is not
// already used, as a single-host prefix. The server's own address and every
// existing peer's allowed-ips are in the used set.
//
// The prefix length is the address width, not a hardcoded 32: an IPv6 server
// subnet allocated as a /32 would be a route across a quarter of the address
// space rather than one host, and the client would mis-route everything.
func allocateWGAddress(serverCIDR string, used map[netip.Addr]bool) (netip.Prefix, error) {
	prefix, err := netip.ParsePrefix(serverCIDR)
	if err != nil {
		return netip.Prefix{}, fmt.Errorf("mgmt: invalid server address %q: %w", serverCIDR, err)
	}
	network := prefix.Masked()
	addr := network.Addr()
	for {
		addr = addr.Next()
		if !addr.IsValid() || !prefix.Contains(addr) {
			return netip.Prefix{}, fmt.Errorf("mgmt: no free address in %s", network)
		}
		// IPv4 reserves the all-ones host as the subnet broadcast; handing it
		// to a peer yields an address the host stack will not source from.
		// IPv6 has no broadcast, so the last address there is usable.
		if addr.Is4() && !prefix.Contains(addr.Next()) {
			return netip.Prefix{}, fmt.Errorf("mgmt: no free address in %s", network)
		}
		if used[addr] {
			continue
		}
		return netip.PrefixFrom(addr, addr.BitLen()), nil
	}
}

// splitEndpoint resolves the operator's endpoint into the host and port the
// client config carries in separate options. A port the operator typed wins
// (the panel prompts for "host[:port]"), then the listener's configured port,
// then the client's own default. A bare IPv6 literal has no port to find and
// SplitHostPort rejects it, which is the host-only answer we want.
func splitEndpoint(endpoint, serverPort, clientDefault string) (host, port string) {
	host = endpoint
	if h, p, err := net.SplitHostPort(endpoint); err == nil {
		host = h
		if p != "" {
			return host, p
		}
	}
	if serverPort != "" {
		return host, serverPort
	}
	return host, clientDefault
}

// withPortRequired appends a port to a host-only endpoint unconditionally --
// the server's configured port, or the default. This is the WireGuard family's
// counterpart to splitEndpoint, and the difference is deliberate: a WireGuard
// endpoint option genuinely is a host:port pair, with no separate port option
// to put the number in, and a client given a bare host dials port 0.
func withPortRequired(endpoint, serverPort, def string) string {
	if endpoint == "" {
		return endpoint
	}
	if _, _, err := net.SplitHostPort(endpoint); err == nil {
		return endpoint
	}
	if serverPort != "" {
		return net.JoinHostPort(endpoint, serverPort)
	}
	return net.JoinHostPort(endpoint, def)
}

// requireDeclaredOptions fails a generation that produced a profile the client
// would refuse to dial. Not every required option is derivable -- ikev2's local
// identity is the client's to choose, and nebula's per-host certificate has to
// be issued by the CA -- and the alternative is handing back a profile that
// looks complete, is saved, and errors at connect time with no hint that the
// generator was the one that came up short. The message names the keys so the
// operator can re-run with them as overrides.
func requireDeclaredOptions(protocol string, opts map[string]string) error {
	specs, ok := client.ClientOptsFor(protocol)
	if !ok {
		return nil
	}
	var missing []string
	for _, sp := range specs {
		if sp.Required && opts[sp.Key] == "" {
			missing = append(missing, sp.Key)
		}
	}
	if len(missing) == 0 {
		return nil
	}
	slices.Sort(missing)
	return fmt.Errorf("mgmt: a %s client also needs %s; pass them in overrides",
		protocol, strings.Join(missing, ", "))
}

// validateOverrides rejects an override for a key the protocol's client OptSpec
// does not declare, so a typo fails loudly instead of being silently dropped by
// the parse.
func validateOverrides(protocol string, overrides map[string]string) error {
	if len(overrides) == 0 {
		return nil
	}
	declared := map[string]bool{}
	if specs, ok := client.ClientOptsFor(protocol); ok {
		for _, sp := range specs {
			declared[sp.Key] = true
		}
	}
	for k := range overrides {
		if !declared[k] {
			return fmt.Errorf("mgmt: %q is not a %s client option", k, protocol)
		}
	}
	return nil
}
