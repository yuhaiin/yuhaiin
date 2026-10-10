// Adapted from xen0bit/veepin (MIT), Copyright (c) 2026 Remy. See THIRD_PARTY_LICENSE.
package native

import (
	"bufio"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"
)

const (
	clientAuthTypePassword = 1
	connectionTCP          = 0
	protocolVersion        = 400
	protocolBuild          = 9799
	clientStr              = "yuhaiin SoftEther-compatible Client"
)

var ErrAuth = errors.New("softether: authentication failed")

// ClientSession is the SoftEther VPN client side.
type UDPClientOptions struct {
	Port  uint16
	KeyV2 [128]byte
	KeyV1 [20]byte
}
type UDPServerOptions struct {
	Version      uint32
	KeyV2        [128]byte
	Port         uint16
	ServerIP     net.IP
	ServerCookie uint32
	ClientCookie uint32
}

type ClientSession struct {
	udpServer *UDPServerOptions
	conn      *tls.Conn
	br        *bufio.Reader
	blocks    *blockReader
	host      string // Host: header value, as the reference sends the peer's IP

	mu sync.Mutex

	serverRandom [sha0Size]byte
	uniqueID     [sha0Size]byte

	hubName     string
	sessionName string
	// policy is what the server said this session may do, when it said
	// anything. It is reported by Policy and not enforced; see policy.go.
	policy Policy

	logf func(format string, args ...any)
}

// Policy reports the session policy the server stated in its welcome. The zero
// value is what a server that stated none leaves behind, which is why Access
// being false is not on its own a reason to conclude anything.
func (cs *ClientSession) Policy() Policy { return cs.policy }

// Connect dials a SoftEther VPN server and performs the control exchange.
func Connect(ctx context.Context, raw net.Conn, tlsCfg *tls.Config, host, username, password, hubName string) (*ClientSession, error) {
	return ConnectWithCert(ctx, raw, tlsCfg, host, username, password, hubName, "", "")
}

// ConnectWithCert supports SoftEther native certificate authentication, not a TLS client certificate.
func ConnectWithCert(ctx context.Context, raw net.Conn, tlsCfg *tls.Config, host, username, password, hubName, certPEM, keyPEM string) (*ClientSession, error) {
	return ConnectWithOptions(ctx, raw, tlsCfg, host, username, password, hubName, certPEM, keyPEM, nil)
}

// ConnectWithOptions performs native authentication and optional UDP v2 negotiation.
func ConnectWithOptions(ctx context.Context, raw net.Conn, tlsCfg *tls.Config, host, username, password, hubName, certPEM, keyPEM string, udp *UDPClientOptions) (_ *ClientSession, err error) {
	if raw == nil {
		return nil, errors.New("softether: nil transport")
	}
	if tlsCfg == nil {
		_ = raw.Close()
		return nil, errors.New("softether: missing TLS config")
	}
	conn := tls.Client(raw, tlsCfg)
	defer func() {
		if err != nil {
			_ = conn.Close()
		}
	}()
	if err := conn.HandshakeContext(ctx); err != nil {
		return nil, fmt.Errorf("softether: TLS handshake: %w", err)
	}
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
		defer func() { _ = conn.SetDeadline(time.Time{}) }()
	}
	cs := &ClientSession{conn: conn, br: bufio.NewReader(conn), host: host, hubName: hubName, logf: func(string, ...any) {}}
	if _, err := rand.Read(cs.uniqueID[:]); err != nil {
		return nil, fmt.Errorf("softether: random id: %w", err)
	}
	if err := writeSignature(conn, host); err != nil {
		return nil, fmt.Errorf("softether: signature: %w", err)
	}
	if err := cs.hello(); err != nil {
		return nil, err
	}
	if err := cs.login(username, password, certPEM, keyPEM, udp); err != nil {
		return nil, err
	}
	return cs, nil
}

// hello reads the server's hello, which arrives unprompted as the response to
// the signature POST. The client sends no hello of its own -- ClientUploadAuth2
// goes straight from ClientDownloadHello to the login PACK.
func (cs *ClientSession) hello() error {
	resp, err := cs.readPack()
	if err != nil {
		return fmt.Errorf("hello response: %w", err)
	}
	if resp.GetStr("hello") == "" {
		return fmt.Errorf("softether: no hello in the server's first PACK")
	}

	random := resp.GetData("random")
	if len(random) != sha0Size {
		return fmt.Errorf("softether: server challenge is %d octets, want %d", len(random), sha0Size)
	}
	copy(cs.serverRandom[:], random)
	return nil
}

func (cs *ClientSession) login(username, password, certPEM, keyPEM string, udp *UDPClientOptions) error {
	var securePass [sha0Size]byte
	certMode := certPEM != "" || keyPEM != ""
	if !certMode {
		securePass = securePassword(hashPassword(username, password), cs.serverRandom)
	}

	// PackLoginWithPassword's field set, in its order. authtype is not
	// optional: the server switches on it to decide which credential to look
	// for, and a login without it is read as anonymous.
	req := NewPack()
	req.Add("method", TypeStr, StrValue("login"))
	req.Add("hubname", TypeStr, StrValue(cs.hubName))
	req.Add("username", TypeStr, StrValue(username))
	if certMode {
		cert, signature, err := signClientChallenge(certPEM, keyPEM, cs.serverRandom[:])
		if err != nil {
			return err
		}
		req.Add("authtype", TypeInt, IntValue(3)) // CLIENT_AUTHTYPE_CERT (Cedar.h)
		req.Add("cert", TypeData, DataValue(cert))
		req.Add("sign", TypeData, DataValue(signature))
	} else {
		req.Add("authtype", TypeInt, IntValue(clientAuthTypePassword))
		req.Add("secure_password", TypeData, DataValue(securePass[:]))
	}
	// The client identification the server logs and rate-limits on.
	// PackAddClientVersion's three fields, and then the same three again under
	// the names the hello half uses -- the reference sends both sets and the
	// server reads from both, so sending one is sending half a login.
	req.Add("client_str", TypeStr, StrValue(clientStr))
	req.Add("client_ver", TypeInt, IntValue(protocolVersion))
	req.Add("client_build", TypeInt, IntValue(protocolBuild))
	req.Add("hello", TypeStr, StrValue(clientStr))
	req.Add("version", TypeInt, IntValue(protocolVersion))
	req.Add("build", TypeInt, IntValue(protocolBuild))
	req.Add("client_id", TypeInt, IntValue(0))
	req.Add("protocol", TypeInt, IntValue(connectionTCP))

	// The session parameters. These are not decoration: the server builds the
	// session from them, and a login that omits max_connection asks for a
	// session with no connections in it -- which is granted, answered with a
	// welcome, and then torn down before a single frame moves. That failure
	// looks exactly like a data-path bug and is a login one.
	req.Add("max_connection", TypeInt, IntValue(1))
	req.Add("use_encrypt", TypeInt, IntValue(1))
	req.Add("use_compress", TypeInt, IntValue(0))
	req.Add("half_connection", TypeInt, IntValue(0))
	req.Add("qos", TypeInt, IntValue(0))
	req.Add("require_bridge_routing_mode", TypeInt, IntValue(0))
	req.Add("require_monitor_mode", TypeInt, IntValue(0))
	req.Add("unique_id", TypeData, DataValue(cs.uniqueID[:]))

	if udp != nil && udp.Port != 0 {
		req.Add("use_udp_acceleration", TypeInt, IntValue(1))
		req.Add("udp_acceleration_version", TypeInt, IntValue(2))
		req.Add("udp_acceleration_max_version", TypeInt, IntValue(2))
		// PackAddIp on an unspecified IPv4 address is an integer zero.
		req.Add("udp_acceleration_client_ip", TypeInt, IntValue(0))
		req.Add("udp_acceleration_client_port", TypeInt, IntValue(uint32(udp.Port)))
		req.Add("udp_acceleration_client_key", TypeData, DataValue(udp.KeyV1[:]))
		req.Add("udp_acceleration_client_key_v2", TypeData, DataValue(udp.KeyV2[:]))
		req.Add("support_udp_accel_fast_disconnect_detect", TypeInt, IntValue(1))
	}
	if err := cs.writePack(req); err != nil {
		return err
	}

	resp, err := cs.readPack()
	if err != nil {
		return fmt.Errorf("auth response: %w", err)
	}
	// The reference signals failure with an "error" element and success with a
	// welcome PACK that has no such element. Checking only for error == 0
	// would accept any PACK at all, including one from a peer that answered
	// something else entirely.
	if code := resp.GetInt("error"); code != 0 {
		return fmt.Errorf("%w: server returned error %d", ErrAuth, code)
	}
	if resp.GetStr("session_name") == "" {
		return fmt.Errorf("%w: login answered without a welcome", ErrAuth)
	}

	if udp != nil && resp.GetInt("use_udp_acceleration") != 0 &&
		resp.GetInt("udp_acceleration_version") == 2 && resp.GetInt("udp_acceleration_use_encryption") != 0 {
		port := resp.GetInt("udp_acceleration_server_port")
		key := resp.GetData("udp_acceleration_server_key_v2")
		sc, cc := resp.GetInt("udp_acceleration_server_cookie"), resp.GetInt("udp_acceleration_client_cookie")
		if port > 0 && port < 65536 && len(key) == 128 && sc != 0 && cc != 0 {
			cfg := &UDPServerOptions{Version: 2, Port: uint16(port), ServerCookie: sc, ClientCookie: cc}
			copy(cfg.KeyV2[:], key)
			if resp.GetInt("udp_acceleration_server_ip@ipv6_bool") != 0 {
				ip := resp.GetData("udp_acceleration_server_ip@ipv6_array")
				if len(ip) == 16 {
					cfg.ServerIP = net.IP(append([]byte(nil), ip...))
				}
			} else {
				a := resp.GetInt("udp_acceleration_server_ip")
				cfg.ServerIP = net.IPv4(byte(a), byte(a>>8), byte(a>>16), byte(a>>24))
				if cfg.ServerIP.Equal(net.IPv4zero) {
					cfg.ServerIP = nil
				}
			}
			cs.udpServer = cfg
		}
	}
	cs.sessionName = resp.GetStr("session_name")
	// The server's policy, if it sent one. It is recorded rather than enforced:
	// see getPolicy for why Access cannot be acted on, and note that the
	// reference client does not act on it either. Logging a session the server
	// says has no access is still worth doing -- it turns "the tunnel is up and
	// carries nothing" into a line that names the reason.
	if policy, ok := getPolicy(resp); ok {
		cs.policy = policy
		if !policy.Access {
			cs.logf("softether: the server's policy grants this session no access")
		}
	}
	// assigned_ip is this implementation's own extension: SoftEther assigns no
	// address in the protocol, because the segment is layer 2 and addressing
	// comes from DHCP or static configuration inside it. A real server does
	// not send this and the field stays nil, which is correct -- see
	// softether.Dial, which does not depend on it.
	if s := resp.GetStr("assigned_ip"); s != "" {
		_ = s // veepin-only assigned_ip extension; native SoftEther uses DHCP
	}
	return nil
}

// WriteFrame sends an Ethernet frame to the server as a single-block burst.
func (cs *ClientSession) WriteFrame(frame []byte) error {
	cs.mu.Lock()
	defer cs.mu.Unlock()
	return writeBlocks(cs.conn, [][]byte{frame})
}

// ReadFrame reads the next Ethernet frame from the server.
//
// The returned slice aliases the session's read buffer and is only valid until
// the next call, matching every other inbound parser in the tree.
func (cs *ClientSession) ReadFrame() ([]byte, error) {
	if cs.blocks == nil {
		cs.blocks = newBlockReader(cs.br)
	}
	return cs.blocks.next()
}

// WriteKeepAlive sends a keepalive block. The data path is otherwise silent
// when nothing is flowing, and a SoftEther server times a session out.
func (cs *ClientSession) WriteKeepAlive() error {
	cs.mu.Lock()
	defer cs.mu.Unlock()
	return writeKeepAlive(cs.conn)
}

// Close closes the client session.
func (cs *ClientSession) Close() error {
	return cs.conn.Close()
}

// readPack reads one PACK from the connection's next HTTP response.
func (cs *ClientSession) readPack() (*Pack, error) {
	return recvPackHTTP(cs.br, false)
}

// writePack sends a PACK as the body of an HTTP POST.
func (cs *ClientSession) writePack(p *Pack) error {
	cs.mu.Lock()
	defer cs.mu.Unlock()
	return sendPackHTTP(cs.conn, p, false, cs.host)
}

// SetReadDeadline bounds DHCP negotiation.
func (cs *ClientSession) SetReadDeadline(t time.Time) error { return cs.conn.SetReadDeadline(t) }

// signClientChallenge matches Cedar RsaSignEx: SHA-1 of the 20-byte server
// challenge, encoded as an RSA PKCS#1 v1.5 signature. The private key never
// crosses the wire and the certificate is sent in DER form.
func signClientChallenge(certPEM, keyPEM string, challenge []byte) ([]byte, []byte, error) {
	if len(challenge) != sha0Size {
		return nil, nil, errors.New("softether: invalid challenge length")
	}
	cb, _ := pem.Decode([]byte(certPEM))
	if cb == nil || cb.Type != "CERTIFICATE" {
		return nil, nil, errors.New("softether: invalid client certificate PEM")
	}
	cert, err := x509.ParseCertificate(cb.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("softether: parse certificate: %w", err)
	}
	kb, _ := pem.Decode([]byte(keyPEM))
	if kb == nil {
		return nil, nil, errors.New("softether: invalid client private key PEM")
	}
	var key *rsa.PrivateKey
	switch kb.Type {
	case "RSA PRIVATE KEY":
		key, err = x509.ParsePKCS1PrivateKey(kb.Bytes)
	case "PRIVATE KEY":
		var parsed any
		parsed, err = x509.ParsePKCS8PrivateKey(kb.Bytes)
		if err == nil {
			var ok bool
			key, ok = parsed.(*rsa.PrivateKey)
			if !ok {
				return nil, nil, errors.New("softether: client authentication requires an RSA key")
			}
		}
	default:
		return nil, nil, errors.New("softether: unsupported client key format")
	}
	if err != nil {
		return nil, nil, fmt.Errorf("softether: parse RSA client key: %w", err)
	}
	pub, ok := cert.PublicKey.(*rsa.PublicKey)
	if !ok || pub.E != key.E || pub.N.Cmp(key.N) != 0 {
		return nil, nil, errors.New("softether: certificate does not match RSA private key")
	}
	digest := sha1.Sum(challenge)
	signature, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA1, digest[:])
	if err != nil {
		return nil, nil, fmt.Errorf("softether: sign challenge: %w", err)
	}
	return cert.Raw, signature, nil
}

// UDPOptions reports the negotiated native UDP v2 transport, if the server accepted it.
func (cs *ClientSession) UDPOptions() *UDPServerOptions { return cs.udpServer }
