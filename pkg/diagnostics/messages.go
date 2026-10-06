package diagnostics

// Report text remains usable by native clients without a translation bundle.
func explanation(code string) string {
	if message, ok := reportMessages[code]; ok {
		return message
	}
	return code
}

var reportMessages = map[string]string{
	"ipv6_disabled":           "IPv6 is disabled in the core settings.",
	"unavailable":             "This check is unavailable.",
	"no_selected_node":        "No TCP node is selected. Routing may use a direct or tagged outbound.",
	"probe_failed":            "The probe failed. Raw errors are excluded to protect node credentials.",
	"tls_verification_failed": "TLS certificate verification failed for this target. Check the target certificate, clock and TLS interception.",
	"connection_refused":      "The connection was refused.",
	"network_unreachable":     "The network or host is unreachable.",
	"dns_failed":              "A DNS lookup failed while establishing this connection.",
	"timeout":                 "The probe timed out.",
	"canceled":                "The probe was canceled.",
	"blocked":                 "The request was blocked.",
	"no_tun":                  "No TUN is configured; this can be expected with a proxy inbound.",
	"tun_disabled":            "Configured TUN listeners are disabled.",
	"tun_not_running":         "An enabled TUN has no registered listener. Check startup logs and device permissions.",
	"tun_capture_unverified":  "The TUN listener is registered. Counters show ingress since startup; current system capture and forwarding still need verification.",
	"no_dns_records":          "No records were returned for this address family. This alone does not prove DNS failure.",
	"dns_resolved":            "Real addresses were returned through the configured resolver/hosts path; cached answers may be used.",
	"tcp_connected":           "Direct TCP port 443 connected to this fixed IP without DNS.",
	"https_response":          "TLS verification succeeded and an HTTP response was received.",
	"route_selected_node":     "The target routes through the selected TCP node. Actual app traffic may differ by inbound/process rules.",
	"check_dns4":              "The configured A lookup failed while AAAA resolved. Inspect A-record queries and resolver policy.",
	"check_dns6":              "The configured AAAA lookup failed while A resolved. Inspect AAAA-record queries and resolver policy.",
	"check_direct_path":       "Direct IP control probes did not connect. Check interface binding, underlying connectivity and endpoint restrictions; proxy paths may still work.",
	"select_tcp_node":         "Routing requires a selected TCP node, but none is selected. Select a node or choose a direct/tagged route for this target.",
	"check_routed_https":      "Routed HTTPS failed for this target. Compare DNS and route evidence, check the safe error category, and retry another destination.",
	"route_matched":           "The target matched this route. Actual app traffic may differ by inbound/process rules.",
	"route_blocks_target":     "The target matched a blocking rule. Verify whether this is intended.",
	"check_tun_start":         "Check TUN startup errors, VPN/device permissions and whether the enabled inbound was applied.",
	"check_dns":               "Configured DNS probes failed. Inspect the resolver and outbound/routing policy; compare with direct IP probes.",
	"ipv4_path_failed":        "IPv4 control endpoint failed while IPv6 connected. Check the IPv4 underlay and compare another destination.",
	"ipv6_path_failed":        "IPv6 control endpoint failed while IPv4 connected. Check IPv6 addresses, upstream access and routes; compare another destination.",
	"check_route_block":       "Routing blocks this target. Review the match evidence and whether blocking is intended.",
	"check_selected_node":     "Selected TCP node HTTPS failed for this target. Compare another node and destination before attributing a node fault.",
	"check_route_path":        "Selected TCP node HTTPS passed but routed HTTPS failed. Inspect the matched route, resolver, hosts mapping and tagged outbound.",
	"core_path_works":         "Core routed HTTPS passed for this target. If apps still fail, check TUN capture, system routing, app DNS and process/inbound rules.",
	"scope_limit":             "Checks run on the backend device for one target. OS routes, current TUN forwarding, browser DNS, UDP and other destinations need separate confirmation.",
}
