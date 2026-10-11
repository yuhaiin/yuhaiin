package livingreadme

import (
	"bufio"
	"encoding/json"
	"fmt"
	"slices"
	"strings"
)

// interopCell is one cell of the interoperability matrix: the set of interop
// test functions that together prove it, and the peer label shown beside the
// pass/fail mark.
//
// A cell with no tests is untested-by-design (e.g. Fortinet has no open-source
// gateway to run the veepin client against); its Label is emitted verbatim, so
// it can carry a fixed string such as "—†".
type interopCell struct {
	Tests []string
	Label string // peer implementation, or the whole cell for an untested one
}

// interopRow is one protocol's row: the three directional cells, plus whatever
// the host has to provide before the row's peer can run at all.
type interopRow struct {
	Protocol string
	Client   interopCell // veepin client ↔ real server
	Server   interopCell // real client ↔ veepin server
	Self     interopCell // veepin ↔ veepin

	// Modules are kernel modules the HOST must have loaded for this row's peer,
	// beyond the tun/XFRM set every shard gets. They are declared here, beside
	// the tests that need them, for the same reason the shard split is derived
	// from this manifest rather than written in YAML: a requirement recorded
	// only in a workflow drifts from the tests silently, and a cell that skips
	// for want of a module is indistinguishable in a CI table from one nobody
	// wrote.
	//
	// Only L2TPv3 has any, and the reason is unusual enough to be worth stating:
	// its peer IS the Linux kernel, so the peer container configures `ip l2tp`
	// against the host's own modules rather than shipping an implementation.
	Modules []string

	// Images are third-party images this row's cells pull from a registry,
	// declared so the workflow can fetch them with retries before the tests
	// run rather than inside one cell's timeout.
	//
	// The reason is Docker Hub, not veepin. An anonymous pull from a
	// GitHub-hosted runner shares an IP pool with every other such runner, and
	// when that pool is throttled a pull stalls rather than failing: the
	// SoftEther and SSTP shards both died with `compose up: signal: killed`
	// having moved 32 kB of a 2.8 MB layer in fifteen minutes, while the same
	// image pulled in seconds from a developer's machine. Charging that to a
	// cell's timeout reports it as a veepin failure, which is the wrong
	// diagnosis on the wrong component.
	//
	// Only images pulled from a registry belong here. An image built from
	// tests/interop/<peer>/ has no pull to retry.
	Images []string
}

// interopMatrix is the manifest that maps every protocol/direction cell to the
// interop test functions that back it. It is the single source of truth for the
// matrix's shape; the pass/fail marks come from a live test run. Keep this in
// step with tests/interop/interop_test.go — a test named here that no longer
// exists reads as a permanent failure, which is the intended loud signal.
var interopMatrix = []interopRow{
	{
		Protocol: "IKEv2",
		Client: interopCell{Tests: []string{
			"TestInteropVeepinClientStrongswanServer",
			"TestInteropVeepinClientStrongswanServerCert",
			"TestInteropVeepinClientStrongswanServerCertRSA",
			"TestInteropVeepinClientStrongswanServerChaCha20",
			"TestInteropVeepinClientStrongswanServerIPv6",
			"TestInteropVeepinClientStrongswanServerV6Underlay",
			"TestInteropVeepinClientStrongswanServerPQ",
			"TestInteropVeepinClientStrongswanIPTFS",
			"TestInteropIPTFSConstantRate",
			"TestInteropIKEv2CorpusStillMatchesTheLivePeer",
			"TestInteropVeepinClientLibreswanServer",
			"TestInteropVeepinClientLibreswanServerTCP",
		}, Label: "strongSwan (PSK + pubkey ECDSA/RSA, RFC 7383 frag, AES-GCM + ChaCha20, dual-stack, v6 underlay, ML-KEM-768, IP-TFS incl. constant-rate, recorded) + libreswan (incl. RFC 8229/9329 over TCP)"},
		Server: interopCell{Tests: []string{
			"TestInteropStrongswanClientVeepinServer",
			"TestInteropStrongswanClientVeepinServerEAP",
			"TestInteropStrongswanClientVeepinServerFragmented",
			"TestInteropStrongswanClientVeepinServerCertRSA",
			"TestInteropStrongswanClientVeepinServerV6Underlay",
			"TestInteropStrongswanClientVeepinServerIPv6",
			"TestInteropStrongswanClientVeepinServerShaped",
			"TestInteropStrongswanClientVeepinServerPQ",
			"TestInteropStrongswanClientVeepinServerIPTFS",
			"TestInteropLibreswanClientVeepinServer",
			"TestInteropLibreswanClientVeepinServerTCP",
		}, Label: "strongSwan (+ EAP-MSCHAPv2, pubkey RSA, RFC 7383 frag both ways, dual-stack, v6 underlay, TFC-padded, ML-KEM-768, IP-TFS) + libreswan (incl. RFC 8229/9329 over TCP)"},
		Self: interopCell{Tests: []string{
			"TestInteropSelf",
			"TestInteropIKEv2ChildRekey",
			"TestInteropIKEv2IKERekey",
			"TestInteropIPTFSSelf",
		}, Label: "(+ IP-TFS)"},
	},
	{
		Protocol: "WireGuard",
		Client: interopCell{Tests: []string{
			"TestInteropVeepinClientWireguardServer",
			"TestInteropVeepinClientWireguardServerV6",
		}, Label: "wireguard-go (+ IPv6 inner)"},
		Server: interopCell{Tests: []string{
			"TestInteropWireguardClientVeepinServer",
			"TestInteropWireguardClientVeepinServerShaped",
			"TestInteropWireguardClientVeepinServerV6",
			"TestInteropWireguardClientVeepinServerCookie",
			"TestInteropWireguardCorpusStillMatchesTheLivePeer",
		}, Label: "wireguard-go (+ padded, IPv6 inner, cookie-challenged, recorded)"},
		Self: interopCell{Tests: []string{"TestInteropWireguardSelf", "TestInteropWireguardRekey"}},
	},
	{
		Protocol: "OpenVPN",
		Client: interopCell{Tests: []string{
			"TestInteropVeepinClientOpenVPNServer",
			"TestInteropOpenVPNTLSAuth",
			"TestInteropOpenVPNTLSCrypt",
			"TestInteropOpenVPNCBC",
		}, Label: "`openvpn` (×4 variants)"},
		Server: interopCell{Tests: []string{
			"TestInteropOpenVPNClientVeepinServer",
			"TestInteropOpenVPNClientVeepinServerTLSAuth",
			"TestInteropOpenVPNClientVeepinServerTLSCrypt",
			"TestInteropOpenVPNClientVeepinServerShaped",
			"TestInteropOpenVPNClientVeepinServerV6",
		}, Label: "`openvpn` (+ tls-auth, tls-crypt, padded, IPv6 inner)"},
		Self: interopCell{Tests: []string{"TestInteropOpenVPNSelf"}},
	},
	{
		Protocol: "SSTP",
		Client:   interopCell{Tests: []string{"TestInteropVeepinClientSSTPServer"}, Label: "SoftEther"},
		// The SSTP client cell's peer is SoftEther VPN Server, pulled rather
		// than built. See Images on interopRow for why that is declared.
		Images: []string{"siomiz/softethervpn:latest"},
		Server: interopCell{Tests: []string{
			"TestInteropSSTPClientVeepinServer",
			"TestInteropSSTPClientVeepinServerShaped",
		}, Label: "`sstpc`/pppd (+ PPP-padded)"},
		Self: interopCell{Tests: []string{"TestInteropSSTPSelf"}},
	},
	{
		Protocol: "SSH",
		Client:   interopCell{Tests: []string{"TestInteropVeepinClientSSHServer"}, Label: "`sshd` (PermitTunnel)"},
		Server: interopCell{Tests: []string{"TestInteropSSHClientVeepinServer",
			"TestInteropSSHClientVeepinServerShaped"}, Label: "`ssh -w`"},
		Self: interopCell{Tests: []string{"TestInteropSSHSelf"}},
	},
	{
		Protocol: "L2TP/IPsec",
		Client:   interopCell{Tests: []string{"TestInteropVeepinClientL2TPServer"}, Label: "strongSwan + xl2tpd"},
		Server: interopCell{Tests: []string{
			"TestInteropL2TPClientVeepinServer",
			"TestInteropL2TPClientVeepinServerShaped",
		}, Label: "strongSwan + xl2tpd (+ PPP-padded)"},
		Self: interopCell{Tests: []string{"TestInteropL2TPSelf"}},
	},
	{
		Protocol: "AnyConnect",
		Client:   interopCell{Tests: []string{"TestInteropVeepinClientAnyConnectServer"}, Label: "ocserv"},
		Server: interopCell{Tests: []string{
			"TestInteropAnyConnectClientVeepinServer",
			"TestInteropAnyConnectClientVeepinServerDTLS",
			"TestInteropAnyConnectClientVeepinServerShaped",
		}, Label: "openconnect (TLS, DTLS, CSTP-padded)"},
		Self: interopCell{Tests: []string{"TestInteropAnyConnectSelf"}},
	},
	{
		Protocol: "Nebula",
		Client: interopCell{Tests: []string{"TestInteropVeepinNebulaHostReferenceLighthouse",
			"TestInteropVeepinNebulaShaped"}, Label: "`nebula` (lighthouse, shaped)"},
		Server: interopCell{Tests: []string{"TestInteropNebulaHostVeepinLighthouse"}, Label: "`nebula` (host)"},
		Self: interopCell{
			Tests: []string{"TestInteropNebulaSelf", "TestInteropNebulaRelay"},
			Label: "(via lighthouse; relayed with the direct path blocked)",
		},
	},
	{
		Protocol: "MASQUE-IP",
		Client:   interopCell{Tests: []string{"TestInteropVeepinMasqueClientAioquicProxy"}, Label: "aioquic CONNECT-IP"},
		Server: interopCell{Tests: []string{"TestInteropAioquicClientVeepinProxy",
			"TestInteropAioquicClientVeepinProxyShaped"}, Label: "aioquic CONNECT-IP"},
		Self: interopCell{Tests: []string{"TestInteropMasqueSelf"}},
	},
	{
		Protocol: "MASQUE-UDP",
		Client:   interopCell{Tests: []string{"TestInteropVeepinUDPClientAioquicProxy"}, Label: "aioquic CONNECT-UDP"},
		Server:   interopCell{Tests: []string{"TestInteropAioquicUDPClientVeepinProxy"}, Label: "aioquic CONNECT-UDP"},
		Self:     interopCell{Tests: []string{"TestInteropMasqueUDPSelf"}},
	},
	{
		Protocol: "Fortinet",
		Client:   interopCell{Label: "—†"},
		Server: interopCell{Tests: []string{
			"TestInteropOpenconnectFortinetClientVeepinServer",
			"TestInteropOpenconnectFortinetDTLS",
			"TestInteropOpenconnectFortinet2FA",
			"TestInteropOpenconnectFortinetClientVeepinServerShaped",
		}, Label: "openconnect (TLS, DTLS, 2FA, PPP-padded)"},
		Self: interopCell{Tests: []string{"TestInteropFortinetSelf"}, Label: "(over DTLS)"},
	},
	{
		Protocol: "GlobalProtect",
		Client:   interopCell{Label: "—†"},
		Server: interopCell{Tests: []string{
			"TestInteropOpenconnectGPClientVeepinServer",
			"TestInteropOpenconnectGPClientVeepinServerESP",
			"TestInteropOpenconnectGPClientVeepinServerShaped",
		}, Label: "openconnect (SSL tunnel, ESP, padded)"},
		Self: interopCell{Tests: []string{"TestInteropGPSelf"}, Label: "(over ESP)"},
	},
	{
		Protocol: "Cisco IPsec",
		Client: interopCell{Tests: []string{
			"TestInteropVeepinCiscoClientStrongSwanServer",
		}, Label: "strongSwan (aggressive + XAuth)"},
		Server: interopCell{Tests: []string{
			"TestInteropStrongSwanCiscoClientVeepinServer",
			"TestInteropStrongSwanCiscoClientVeepinServerShaped",
		}, Label: "strongSwan (Mode-Config, TFC-padded)"},
		Self: interopCell{Tests: []string{"TestInteropCiscoSelf"}},
	},
	{
		Protocol: "Ivanti Connect Secure",
		Client:   interopCell{Label: "—†"},
		Server: interopCell{Tests: []string{
			"TestInteropOpenconnectPulseClientVeepinServer",
			"TestInteropOpenconnectPulseClientVeepinServerESP",
			"TestInteropOpenconnectPulseClientVeepinServerShaped",
		}, Label: "openconnect (IF-T/TLS, ESP, padded)"},
		Self: interopCell{Tests: []string{"TestInteropPulseSelf"}, Label: "(over ESP)"},
	},
	// SoftEther's client cell is built, against SoftEther VPN Server itself.
	// This comment used to explain why both cross-implementation cells were
	// "—‡" and to argue that nothing structural was stopping them. That was
	// half right: nothing structural was stopping the *cell*, and what the
	// cell then found was that the protocol underneath it had never been
	// interoperable at all — PACK's byte order, three string encodings, the
	// password hash, the HTTP layer and the block framing were each wrong, and
	// each invisible to the Self cell because both ends were wrong together.
	//
	// That is the second time this row has taught the same lesson. The Self
	// column was a dash until building it found neither end pumped frames; the
	// Client column was a dash until building it found five wire bugs. Both
	// times the dash was read as "nobody has spent the afternoon" and both
	// times it was hiding something that a peer, and only a peer, could see.
	//
	// The Server cell carried "‡" — work outstanding rather than a limitation —
	// and it is now built, which makes this row the third time it taught the
	// same lesson in a row. The two things this comment named as what the cell
	// needed were both wrong. PackWelcome's policy is not required: PackGetPolicy
	// zero-fills, so a welcome without one parses and the client enforces none
	// of the fields locally. The additional connections never happen: the
	// welcome advertises max_connection=1 and ClientAdditionalConnectChance
	// compares the live count against exactly that. What actually blocked it was
	// one layer lower and had not been guessed at — vpnclient opens with `GET /`
	// and posts the signature second, and veepin read one request and judged it.
	//
	// Two months of reasoning produced two confident blockers, neither real, and
	// missed the one that was. That is not an argument for reasoning more
	// carefully.
	{
		Protocol: "SoftEther VPN",
		Client: interopCell{
			Tests: []string{"TestInteropVeepinClientSoftEtherServer"},
			Label: "SoftEther VPN Server (native SE-VPN, SecureNAT)",
		},
		Server: interopCell{
			Tests: []string{"TestInteropSoftEtherClientVeepinServer"},
			Label: "SoftEther VPN `vpnclient`",
		},
		Self: interopCell{
			Tests: []string{"TestInteropSoftEtherSelf", "TestInteropSoftEtherShaped"},
			Label: "(layer 2, switched; shaped)",
		},
		// The same image the SSTP row pulls, for the same reason.
		Images: []string{"siomiz/softethervpn:latest"},
	},
	{
		Protocol: "AmneziaWG",
		Client:   interopCell{Tests: []string{"TestInteropVeepinClientAmneziaWGServer"}, Label: "amneziawg-go"},
		Server:   interopCell{Tests: []string{"TestInteropAmneziaWGClientVeepinServer"}, Label: "amneziawg-go"},
		Self:     interopCell{Tests: []string{"TestInteropAmneziaWGSelf"}, Label: "(H1-H4, S1-S4, junk)"},
	},
	{
		Protocol: "L2TPv3",
		// The peer for both kernel cells IS the Linux kernel, so they need
		// l2tp_eth and l2tp_netlink on the HOST -- see Modules below, which is
		// what now gets them there. GitHub's runners boot an Azure kernel whose
		// l2tp modules live in a separate package, so for as long as nobody
		// installed it the cells skipped, and a skip renders as ✗.
		Client: interopCell{Tests: []string{"TestInteropVeepinClientKernelL2TPv3Server"},
			Label: "Linux kernel (`ip l2tp`, 8-octet asymmetric cookies)"},
		Server: interopCell{Tests: []string{"TestInteropKernelL2TPv3ClientVeepinServer"},
			Label: "Linux kernel (`ip l2tp`)"},
		Self:    interopCell{Tests: []string{"TestInteropL2TPv3Self"}, Label: "(shaped)"},
		Modules: []string{"l2tp_eth", "l2tp_netlink"},
	},
	// The ten pq- variants, each a second registry name under which post-quantum
	// cryptography is mandatory rather than negotiated. They are rows rather than
	// footnotes on their base protocols' rows for the reason
	// doc/pq-variants-plan.md gives for the naming scheme itself: this matrix is
	// keyed by protocol name, so a variant with a row gets a published,
	// CI-verified claim and its own shard, and a variant folded into its base's
	// row gets a sentence in a label and no throughput figure.
	//
	// They are NOT counted in "sixteen production protocols" -- client.Variants()
	// is a separate namespace from client.Protocols(), and pq-ikev2 is IKEv2 with
	// a floor under it rather than a seventeenth protocol.
	//
	// Read the "—†" cells as what doc/security.md says they are: for most of
	// these variants no third-party peer exists to test against, and that is a
	// fact about the ecosystem in 2026 rather than a gap in this suite. Those
	// rows are veepin↔veepin evidence only.
	{
		Protocol: "pq-ikev2",
		// strongSwan proves the KEY EXCHANGE half. Its ML-DSA authentication is
		// on a branch targeted at 6.1.0, so the AUTH half has no peer yet --
		// which is why the client direction, where veepin would present the
		// ML-DSA certificate, has none.
		Client: interopCell{Label: "—†"},
		Server: interopCell{Tests: []string{
			"TestInteropPQIKEv2ServerAcceptsAPostQuantumPeer",
			"TestInteropPQIKEv2ServerRefusesAClassicalPeer",
		}, Label: "strongSwan (ML-KEM-768 required, **and a classical initiator refused**)"},
		Self: interopCell{Tests: []string{"TestInteropPQIKEv2Self"}},
	},
	{
		Protocol: "pq-openvpn",
		// The only variant with a third-party peer for BOTH halves, and the only
		// one where authentication is mutual -- so each end's ML-DSA-65
		// signature is verified by the other implementation. openvpn 2.6.14
		// links OpenSSL 3.5.7.
		Client: interopCell{Tests: []string{"TestInteropPQOpenVPNVeepinClientRealServer"},
			Label: "`openvpn` 2.6.14 (ML-DSA-65 mutual, ML-KEM-only groups)"},
		Server: interopCell{Tests: []string{"TestInteropPQOpenVPNRealClientVeepinServer"},
			Label: "`openvpn` 2.6.14 (ML-DSA-65 mutual, ML-KEM-only groups)"},
		Self: interopCell{Tests: []string{"TestInteropPQOpenVPNSelf"}},
	},
	{
		Protocol: "pq-ssh",
		// Key exchange only, by the single named exception in
		// pqpolicy.SSHKeyExchangeOnly: SSH has no post-quantum signature
		// algorithm anywhere. Both peers pin KexAlgorithms to one name, so
		// neither cell can pass on a classical fallback.
		Client: interopCell{Tests: []string{"TestInteropPQSSHClientSSHD"},
			Label: "OpenSSH 10.0 requiring `mlkem768x25519-sha256` (kex only)"},
		Server: interopCell{Tests: []string{"TestInteropPQSSHClientVeepinServer"},
			Label: "OpenSSH 10.0 requiring `mlkem768x25519-sha256` (kex only)"},
		Self: interopCell{Tests: []string{"TestInteropPQSSHSelf"}},
	},
	{
		Protocol: "pq-anyconnect",
		Client:   interopCell{Label: "—†"},
		Server:   interopCell{Label: "—†"},
		Self:     interopCell{Tests: []string{"TestInteropPQAnyConnectSelf"}, Label: "(over TLS: `-no-dtls` is forced)"},
	},
	{
		Protocol: "pq-fortinet",
		Client:   interopCell{Label: "—†"},
		Server:   interopCell{Label: "—†"},
		Self:     interopCell{Tests: []string{"TestInteropPQFortinetSelf"}, Label: "(over TLS: `-no-dtls` is forced)"},
	},
	{
		Protocol: "pq-gp",
		Client:   interopCell{Label: "—†"},
		Server:   interopCell{Label: "—†"},
		Self:     interopCell{Tests: []string{"TestInteropPQGPSelf"}, Label: "(over ESP)"},
	},
	{
		Protocol: "pq-pulse",
		Client:   interopCell{Label: "—†"},
		Server:   interopCell{Label: "—†"},
		Self:     interopCell{Tests: []string{"TestInteropPQPulseSelf"}, Label: "(over ESP)"},
	},
	{
		Protocol: "pq-sstp",
		Client:   interopCell{Label: "—†"},
		Server:   interopCell{Label: "—†"},
		Self:     interopCell{Tests: []string{"TestInteropPQSSTPSelf"}},
	},
	{
		Protocol: "pq-masque",
		// aioquic brings its own hand-written TLS 1.3 in Python: measured at
		// 1.3.0, its Group enum has no ML-KEM member and its
		// SignatureAlgorithm enum no ML-DSA. There is no peer and none in
		// prospect.
		Client: interopCell{Label: "—†"},
		Server: interopCell{Label: "—†"},
		Self:   interopCell{Tests: []string{"TestInteropPQMasqueSelf"}},
	},
	{
		Protocol: "pq-softether",
		Client:   interopCell{Label: "—†"},
		Server:   interopCell{Label: "—†"},
		Self:     interopCell{Tests: []string{"TestInteropPQSoftEtherSelf"}, Label: "(layer 2, switched)"},
	},
	{
		Protocol: "TOY*",
		Client:   interopCell{Tests: []string{"TestInteropVeepinToyClientReferencePeer"}, Label: "independent Python peer"},
		Server:   interopCell{Tests: []string{"TestInteropToyClientVeepinServer"}, Label: "independent Python peer"},
		Self:     interopCell{Tests: []string{"TestInteropToySelf"}},
	},
}

// TestResults maps an interop test function name to whether it passed. A test
// that failed, was skipped, or never ran is false (absent).
type TestResults map[string]bool

// ParseTestResults reads the newline-delimited JSON that `go test -json` emits
// and returns the pass/fail verdict for every top-level test. A test passes only
// if its final action is "pass"; "fail" and "skip" both count as not-passed. Sub
// tests (names containing "/") are ignored — the matrix keys on the parent.
func ParseTestResults(jsonOut string) TestResults {
	results := TestResults{}
	sc := bufio.NewScanner(strings.NewReader(jsonOut))
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if !strings.HasPrefix(line, "{") {
			continue
		}
		var ev struct {
			Action string `json:"Action"`
			Test   string `json:"Test"`
		}
		if err := json.Unmarshal([]byte(line), &ev); err != nil {
			continue
		}
		if ev.Test == "" || strings.Contains(ev.Test, "/") {
			continue
		}
		switch ev.Action {
		case "pass":
			results[ev.Test] = true
		case "fail", "skip":
			if _, ok := results[ev.Test]; !ok {
				results[ev.Test] = false
			}
		}
	}
	return results
}

// SkippedMatrixTests returns, sorted, the matrix-backing tests that the run
// skipped rather than passing or failing.
//
// It exists because a skip and a failure are the same value in TestResults, and
// therefore the same "✗" in the rendered table — a mark that says "veepin does
// not interoperate" for a cell whose peer never started. That is precisely the
// false ✗ the Fortinet "—†" precedent exists to avoid, and it sat on the front
// page for both L2TPv3 kernel cells for as long as the runners lacked the l2tp
// modules.
//
// The caller's job is to refuse to publish such a run, not to invent a third
// mark for it. A table is a claim about what was tested; a run that did not test
// a cell has nothing to say about it, and the honest response is to fix the
// environment and run again. Only tests the manifest names are considered, so a
// skip in an unrelated helper is not the README's business.
func SkippedMatrixTests(jsonOut string) []string {
	inMatrix := map[string]bool{}
	for _, row := range interopMatrix {
		for _, c := range []interopCell{row.Client, row.Server, row.Self} {
			for _, name := range c.Tests {
				inMatrix[name] = true
			}
		}
	}

	// Final action wins, exactly as in ParseTestResults: a test that skipped a
	// subtest and then passed is a pass.
	final := map[string]string{}
	sc := bufio.NewScanner(strings.NewReader(jsonOut))
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if !strings.HasPrefix(line, "{") {
			continue
		}
		var ev struct {
			Action string `json:"Action"`
			Test   string `json:"Test"`
		}
		if err := json.Unmarshal([]byte(line), &ev); err != nil {
			continue
		}
		if ev.Test == "" || strings.Contains(ev.Test, "/") || !inMatrix[ev.Test] {
			continue
		}
		switch ev.Action {
		case "pass", "fail", "skip":
			final[ev.Test] = ev.Action
		}
	}

	var skipped []string
	for name, action := range final {
		if action == "skip" {
			skipped = append(skipped, name)
		}
	}
	slices.Sort(skipped)
	return skipped
}

// renderCell renders one matrix cell against the results. An untested cell (no
// tests) emits its Label verbatim. A tested cell shows ✓ when every backing test
// passed and ✗ otherwise, followed by the peer label if any.
func renderCell(c interopCell, results TestResults) string {
	if len(c.Tests) == 0 {
		if c.Label == "" {
			return "—"
		}
		return c.Label
	}
	mark := "✓"
	for _, name := range c.Tests {
		if !results[name] {
			mark = "✗"
			break
		}
	}
	if c.Label == "" {
		return mark
	}
	return mark + " " + c.Label
}

// RenderInterop renders the interoperability matrix from a live set of test
// results, followed by a provenance footer. The manifest fixes the rows and peer
// labels; only the ✓/✗ marks come from results.
func RenderInterop(results TestResults, meta Meta) string {
	var b strings.Builder
	b.WriteString("| Protocol   | veepin client ↔ real server | real client ↔ veepin server | veepin ↔ veepin (self) |\n")
	b.WriteString("|------------|-----------------------------|-----------------------------|------------------------|\n")
	for _, row := range interopMatrix {
		fmt.Fprintf(&b, "| %s | %s | %s | %s |\n",
			row.Protocol,
			renderCell(row.Client, results),
			renderCell(row.Server, results),
			renderCell(row.Self, results),
		)
	}
	b.WriteString("\n")
	b.WriteString(meta.footer())
	return b.String()
}

// InteropShard is one parallel slice of the interop suite: a name usable as a
// GitHub Actions job and artifact identifier, and the -run regexp that selects
// exactly the tests backing one protocol's row.
type InteropShard struct {
	Name string `json:"name"`
	Run  string `json:"run"`
	// Modules is the row's Modules, carried through so the workflow can load
	// them before the cells run without naming any protocol itself.
	Modules []string `json:"modules"`
	// Images is the row's Images, carried through for the same reason: the
	// workflow pre-pulls them with retries and names no protocol itself.
	Images []string `json:"images"`
}

// InteropShards derives the suite's parallel split from the manifest above, one
// shard per protocol.
//
// Deriving the split rather than listing it separately is what keeps it honest.
// Cells still run serially within a shard, so the suite is bounded by its
// slowest protocol instead of the sum of all of them; but a hand-written shard
// list that drifted from the manifest would quietly stop running whatever it had
// missed, and a test that never runs is indistinguishable from one that passes.
// Adding a protocol row here adds a shard, and there is no way to add one
// without.
//
// A row whose cells are all empty — untested by design — yields no shard.
func InteropShards() []InteropShard {
	shards := make([]InteropShard, 0, len(interopMatrix))
	for _, row := range interopMatrix {
		var tests []string
		for _, c := range []interopCell{row.Client, row.Server, row.Self} {
			tests = append(tests, c.Tests...)
		}
		if len(tests) == 0 {
			continue
		}
		// Empty rather than nil, so the JSON carries [] and never null. The
		// workflow reads this through GitHub's join(), whose behaviour on null is
		// not something to find out from a failing run.
		modules := row.Modules
		if modules == nil {
			modules = []string{}
		}
		images := row.Images
		if images == nil {
			images = []string{}
		}
		shards = append(shards, InteropShard{
			Name:    shardName(row.Protocol),
			Run:     "^(" + strings.Join(tests, "|") + ")$",
			Modules: modules,
			Images:  images,
		})
	}
	return shards
}

// shardName slugs a protocol name into an identifier a workflow can use for a
// job label and an artifact file. "L2TP/IPsec" and "TOY*" are neither.
func shardName(protocol string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(protocol) {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
			continue
		}
		if b.Len() > 0 && b.String()[b.Len()-1] != '-' {
			b.WriteByte('-')
		}
	}
	return strings.Trim(b.String(), "-")
}
