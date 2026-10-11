package softether

// The session policy the server states in its welcome PACK.
//
// SoftEther's POLICY (Cedar/Account.h) is the server's declaration of what a
// session may do: whether it has access at all, which packet classes are
// filtered, how many MAC and IP addresses it may claim, what bandwidth it gets.
// It crosses the wire not as a structure but as three dozen flat elements in
// the welcome PACK, each named "policy:" + the field name -- PackAddPolicy in
// Cedar/Protocol.c, and PackGetPolicy reading them back.
//
// **Sending it is not what made a real client connect, and this comment exists
// so nobody re-derives that the hard way.** internal/softether/README.md used
// to name the missing policy as one of two things blocking SoftEther's own
// client against veepin's server. It was not: PackGetPolicy allocates a
// zeroed POLICY and fills it from whatever elements are present, so a welcome
// with none of them parses -- and the client enforces only two of the fields
// locally (AutoDisconnect and NoSavePassword), for which zero is the
// permissive value. The actual blocker was in the HTTP layer; see
// readSignature.
//
// It is sent anyway, for a reason that is not compatibility: an omitted
// element gives the client the value we wanted *by accident*. "Do not
// auto-disconnect this session" and "we did not mention auto-disconnect" arrive
// identically, and the first is a statement while the second is a coincidence
// that holds only as long as PackGetPolicy keeps zero-filling. Every flag below
// is false because this server enforces no such restriction, which is a fact
// about veepin worth putting on the wire rather than leaving to a default.

// Policy is the subset of SoftEther's POLICY this server has anything to say
// about. The restriction flags are all absent rather than listed: veepin's
// switch enforces none of them, so every one is false, and a struct field per
// unenforced restriction would be three dozen fields that can only hold one
// value.
type Policy struct {
	// Access grants the session any access at all. False is a session that
	// authenticates and then carries nothing, which the reference uses to
	// disable an account without deleting it.
	Access bool
	// MaxConnection is how many TCP connections the session may hold. It is
	// the policy's copy of the welcome's own max_connection, and the reference
	// client takes the welcome's; this one is kept equal so a peer reading
	// either sees the same number.
	MaxConnection uint32
	// TimeOut is the session's idle timeout in SECONDS -- not milliseconds,
	// which is what the welcome's own "timeout" element carries. The two units
	// sit three lines apart in PackWelcome and are easy to conflate.
	TimeOut uint32
	// VLANID tags the session's frames. Zero is untagged, which is what this
	// server does.
	VLANID uint32
}

// defaultPolicy mirrors GetDefaultPolicy (Cedar/Account.c) where veepin agrees
// with it, and differs in one place on purpose: MaxConnection is 1 rather than
// 32, because this server accepts one connection per session and the policy
// should say what is true rather than what the reference's template says.
func defaultPolicy(maxConnection uint32) Policy {
	return Policy{
		Access:        true,
		MaxConnection: maxConnection,
		// GetDefaultPolicy's 20. Seconds.
		TimeOut: 20,
		VLANID:  0,
	}
}

// policyBoolNames is every "policy:" boolean the reference emits, in
// PackAddPolicy's order. They are listed rather than derived because the list
// IS the wire format: a name that drifts is silently read back as false by a
// peer, which for a restriction flag is the permissive answer and therefore
// invisible in a test that only checks a tunnel came up.
//
// Every one of them is a restriction this server does not impose, so all are
// emitted false. Access is not here: it is the one boolean whose value is not
// constant, so it is written by addPolicy directly.
var policyBoolNames = []string{
	// Ver 2
	"DHCPFilter", "DHCPNoServer", "DHCPForce", "NoBridge", "NoRouting",
	"PrivacyFilter", "NoServer", "CheckMac", "CheckIP", "ArpDhcpOnly",
	"MonitorPort", "NoBroadcastLimiter", "FixPassword", "NoQoS",
	// Ver 3
	"RSandRAFilter", "RAFilter", "DHCPv6Filter", "DHCPv6NoServer",
	"NoRoutingV6", "CheckIPv6", "NoServerV6", "NoSavePassword",
	"FilterIPv4", "FilterIPv6", "FilterNonIP",
	"NoIPv6DefaultRouterInRA", "NoIPv6DefaultRouterInRAWhenIPv6",
}

// policyZeroUintNames is every "policy:" integer that is a limit this server
// does not impose. Zero is the reference's own "no limit" for each.
var policyZeroUintNames = []string{
	"MaxMac", "MaxIP", "MaxUpload", "MaxDownload", "MultiLogins",
	"MaxIPv6", "AutoDisconnect",
}

// addPolicy writes the policy into a PACK exactly as PackAddPolicy does: flat
// elements, "policy:" prefix, booleans as ints (PackAddBool is PackAddInt with
// a JSON hint the wire never carries).
func addPolicy(p *Pack, y Policy) {
	p.Add("policy:Access", TypeInt, IntValue(boolInt(y.Access)))
	for _, name := range policyBoolNames {
		p.Add("policy:"+name, TypeInt, IntValue(0))
	}
	p.Add("policy:MaxConnection", TypeInt, IntValue(y.MaxConnection))
	p.Add("policy:TimeOut", TypeInt, IntValue(y.TimeOut))
	for _, name := range policyZeroUintNames {
		p.Add("policy:"+name, TypeInt, IntValue(0))
	}
	p.Add("policy:VLanId", TypeInt, IntValue(y.VLANID))

	// PackAddPolicy's last line, and unlike every flag above it is
	// unconditionally true rather than read from the struct: it declares that
	// the Ver 3 fields are present, which they are because we just wrote them.
	p.Add("policy:Ver3", TypeInt, IntValue(1))
}

// getPolicy reads a policy back, as PackGetPolicy does, and reports separately
// whether the welcome carried one at all.
//
// The second return is not decoration, and it is the reason this cannot simply
// mirror PackGetPolicy. A missing element reads back as zero, so a welcome with
// no policy is indistinguishable from one that grants no Access -- and Access
// is the field a reader would most want to act on. Acting on it without the
// presence flag would refuse every server that omits the policy, which is any
// Ver 2 server and, until the commit that added policy.go, veepin's own.
//
// So presence is answered by an element's existence rather than its value, and
// callers that care must ask. The reference client sidesteps this by not
// enforcing Access at all -- it is a server-side check there -- which is also
// what this client does.
func getPolicy(p *Pack) (Policy, bool) {
	y := Policy{
		Access:        p.GetInt("policy:Access") != 0,
		MaxConnection: p.GetInt("policy:MaxConnection"),
		TimeOut:       p.GetInt("policy:TimeOut"),
		VLANID:        p.GetInt("policy:VLanId"),
	}
	return y, p.Get("policy:Access") != nil
}

func boolInt(b bool) uint32 {
	if b {
		return 1
	}
	return 0
}
