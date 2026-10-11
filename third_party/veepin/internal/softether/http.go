package softether

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"html"
	"io"
	"net/http"
)

// The HTTP layer SE-VPN puts in front of its control PACKs.
//
// A SoftEther connection does not begin with a PACK. It begins with an HTTP
// exchange that looks like a browser fetching a JPEG, and only then are PACKs
// carried as HTTP bodies, one PACK per message, until the connection is
// switched to the raw data path:
//
//	client                                                     server
//	  |-- POST /vpnsvc/connect.cgi  Content-Type: image/jpeg ---->|  the signature
//	  |    body: "VPNCONNECT" (or the watermark blob)             |
//	  |<-- 200 OK  application/octet-stream: PACK{hello,random} --|  ServerUploadHello
//	  |-- POST /vpnsvc/vpn.cgi      application/octet-stream ---->|  PACK{method=login}
//	  |    body: PACK{method,hubname,username,authtype,...}       |
//	  |<-- 200 OK  application/octet-stream: PACK{welcome,...} ---|
//	  |=================== raw blocks, see frame.go ==============|
//
// Two details decide whether a real server answers at all.
//
// **The POST target is not the same for both stages.** The signature goes to
// /vpnsvc/connect.cgi (HTTP_VPN_TARGET2) and every PACK after it to
// /vpnsvc/vpn.cgi (HTTP_VPN_TARGET). ServerDownloadSignature compares the
// target against connect.cgi and answers 404 for anything else, so a client
// that uses one path throughout gets a 404 it will read as a network fault.
//
// **The server accepts a ten-octet string in place of the watermark.**
// ServerDownloadSignature admits a body that is either the WaterMark blob (a
// ~1 KB image, present in the source as a byte array) or exactly the string
// "VPNCONNECT" (HTTP_VPN_TARGET_POSTDATA). The short form is what this sends:
// it is a documented branch of the peer's own acceptance test rather than a
// shortcut around it, and it keeps a kilobyte of somebody else's image data
// out of the tree.
//
// **The signature is not necessarily the first request on the connection.**
// The diagram above is what veepin's own client sends, and it is not what
// SoftEther's client sends: `vpnclient` opens with `GET /` before it posts the
// signature. ServerDownloadSignature is a *loop* -- up to nineteen requests,
// the same count its own Keep-Alive header advertises -- answering anything
// that is not the signature the way a web server would and reading the next
// request. A server that treats the first request as the signature refuses
// every real client on its opening move, which is exactly what this one did
// until a cell was pointed at `vpnclient`.

// The HTTP constants, from SoftEtherVPN/src/Mayaqua/HTTP.h. Named exactly as
// the reference names them so the two can be diffed.
const (
	httpVPNTarget         = "/vpnsvc/vpn.cgi"     // HTTP_VPN_TARGET, every control PACK
	httpVPNTarget2        = "/vpnsvc/connect.cgi" // HTTP_VPN_TARGET2, the signature only
	httpVPNTargetPostData = "VPNCONNECT"          // HTTP_VPN_TARGET_POSTDATA
	httpContentTypePack   = "application/octet-stream"
	httpContentTypeJPEG   = "image/jpeg" // what the signature POST claims to be
	httpContentTypeHTML   = "text/html"  // HTTP_CONTENT_TYPE, the 403 page's
	httpKeepAlive         = "timeout=15; max=19"

	// HTTP_PACK_MAX_SIZE. A control PACK larger than this is refused before
	// the body is read, so a peer cannot make us allocate on its say-so.
	maxHTTPPackSize = 65536

	// HTTP_PACK_RAND_SIZE_MAX, the exclusive bound on the padding element
	// CreateDummyValue appends to every PACK sent over HTTP.
	httpPackRandSizeMax = 1000
)

var (
	// errNotVPNServer is what a peer that speaks HTTP but not this protocol
	// produces -- a plain web server on 443, or a SoftEther whose virtual host
	// is not configured for it.
	errNotVPNServer = errors.New("softether: peer answered HTTP but not the VPN signature")

	errPackTooLarge = errors.New("softether: control message over the 64 KiB HTTP limit")
	errBadStatus    = errors.New("softether: unexpected HTTP status")
)

// writeSignature performs the client's opening POST: the request that tells a
// SoftEther server this connection is a VPN and not a browser.
func writeSignature(w io.Writer, host string) error {
	body := []byte(httpVPNTargetPostData)
	// Written by hand rather than through net/http. The peer parses this with
	// RecvHttpHeader, which is its own line reader, and the exchange is one
	// request and one response on a connection this package then takes over
	// for raw frames -- net/http's client owns the connection it dials and
	// will not hand it back with bytes still unread on it.
	_, err := fmt.Fprintf(w, "POST %s HTTP/1.1\r\nHost: %s\r\nContent-Type: %s\r\nConnection: Keep-Alive\r\nContent-Length: %d\r\n\r\n%s",
		httpVPNTarget2, host, httpContentTypeJPEG, len(body), body)
	return err
}

// readSignature is the server's side of that POST: it reads requests until one
// of them is the signature, answering the others the way ServerDownloadSignature
// does. It returns nil only for a request the reference would have accepted.
//
// The loop is the part that matters and the part that was missing. SoftEther's
// own client opens the connection with `GET /` -- a probe, not a mistake -- and
// only then posts the signature. Reading one request and judging it refused
// every real client on its first move, while veepin's own client, which posts
// the signature immediately, sailed through. That is the mutually-consistent
// shape this tree keeps finding: both ends agreed, and the agreement was with
// nobody else.
func readSignature(br *bufio.Reader, w io.Writer) error {
	for range maxRequestsBeforeSignature {
		req, err := http.ReadRequest(br)
		if err != nil {
			return fmt.Errorf("softether: reading the signature request: %w", err)
		}
		// Bounded by the largest thing the reference will accept here: the
		// watermark plus its random tail (MAX_WATERMARK_SIZE).
		body, berr := io.ReadAll(io.LimitReader(req.Body, maxHTTPPackSize))
		_ = req.Body.Close()
		if berr != nil {
			return fmt.Errorf("softether: reading the signature body: %w", berr)
		}

		if req.Method == http.MethodPost && req.URL.Path == httpVPNTarget2 {
			// The short form, or anything watermark-shaped. The reference
			// compares the full image; accepting any sufficiently long body in
			// its place is deliberate -- the watermark is not a secret, it is
			// not an authenticator, and refusing a real client because its
			// build ships a different image would be a compatibility bug
			// wearing a security hat.
			if !bytes.Equal(body, []byte(httpVPNTargetPostData)) && len(body) < 64 {
				return fmt.Errorf("%w: %d-octet body", errNotVPNServer, len(body))
			}
			return nil
		}

		// Not the signature. A method the reference does not serve ends the
		// connection; a browser-shaped request gets a browser-shaped answer and
		// the loop reads the next one.
		switch req.Method {
		case http.MethodGet, http.MethodHead, http.MethodPost:
			if err := writeForbidden(w, req.URL.Path); err != nil {
				return err
			}
		default:
			return fmt.Errorf("%w: %s %s", errNotVPNServer, req.Method, req.URL.Path)
		}
	}
	return fmt.Errorf("%w: no signature in %d requests", errNotVPNServer, maxRequestsBeforeSignature)
}

// maxRequestsBeforeSignature bounds how many non-signature requests a peer may
// send first. Nineteen is the reference's own `max`, and not a coincidence: it
// is the same number its Keep-Alive header advertises, so a client honouring
// the header cannot exceed it. Without a bound, anything that speaks HTTP holds
// a goroutine and a TLS connection open for as long as it keeps asking.
const maxRequestsBeforeSignature = 19

// writeForbidden answers a non-VPN request the way the reference's
// HttpSendForbidden does -- a 403 with a body, and Connection: Keep-Alive so the
// client sends its next request on the same connection rather than reconnecting.
//
// Written by hand rather than through net/http for the reason writeSignature is:
// this connection is about to stop being HTTP, and net/http's server owns the
// connection it serves.
func writeForbidden(w io.Writer, target string) error {
	body := forbiddenBody(target)
	_, err := fmt.Fprintf(w, "HTTP/1.1 403 Forbidden\r\nKeep-Alive: %s\r\nConnection: Keep-Alive\r\nContent-Type: %s\r\nContent-Length: %d\r\n\r\n%s",
		httpKeepAlive, httpContentTypeHTML, len(body), body)
	return err
}

// forbiddenBody is the reference's http_403_str with its $TARGET$ substituted.
// The wording is copied so a person tcpdumping both servers sees the same page,
// and the target is escaped because it is peer-supplied and lands in HTML.
func forbiddenBody(target string) string {
	return "<!DOCTYPE HTML PUBLIC \"-//IETF//DTD HTML 2.0//EN\">\r\n" +
		"<HTML><HEAD>\r\n<TITLE>403 Forbidden</TITLE>\r\n</HEAD><BODY>\r\n" +
		"<H1>Forbidden</H1>\r\nYou don't have permission to access " +
		html.EscapeString(target) +
		"\r\non this server.<P>\r\n<HR>\r\n<ADDRESS>HTTPS Server</ADDRESS>\r\n</BODY></HTML>\r\n"
}

// sendPackHTTP writes one PACK as an HTTP message body. isServer selects a 200
// response over a POST request, which is the only difference between
// HttpServerSend and HttpClientSend.
func sendPackHTTP(w io.Writer, p *Pack, isServer bool, host string) error {
	p.addDummyValue()

	body, err := p.Encode()
	if err != nil {
		return err
	}
	if len(body) > maxHTTPPackSize {
		return fmt.Errorf("%w: %d octets", errPackTooLarge, len(body))
	}

	var head string
	if isServer {
		head = fmt.Sprintf("HTTP/1.1 200 OK\r\nKeep-Alive: %s\r\nConnection: Keep-Alive\r\nContent-Type: %s\r\nContent-Length: %d\r\n\r\n",
			httpKeepAlive, httpContentTypePack, len(body))
	} else {
		head = fmt.Sprintf("POST %s HTTP/1.1\r\nHost: %s\r\nKeep-Alive: %s\r\nConnection: Keep-Alive\r\nContent-Type: %s\r\nContent-Length: %d\r\n\r\n",
			httpVPNTarget, host, httpKeepAlive, httpContentTypePack, len(body))
	}
	if _, err := io.WriteString(w, head); err != nil {
		return err
	}
	_, err = w.Write(body)
	return err
}

// recvPackHTTP reads one PACK from an HTTP message body.
//
// It skips "noop" PACKs rather than returning them. The reference's
// HttpClientRecv does the same: the server emits a noop to keep a connection
// warm while it is doing something slow, and a client that surfaced one to its
// caller would see it as a protocol error at whatever step it was waiting on.
func recvPackHTTP(br *bufio.Reader, isServer bool) (*Pack, error) {
	for range maxNoopPerSession {
		body, err := readHTTPBody(br, isServer)
		if err != nil {
			return nil, err
		}
		p, err := Decode(body)
		if err != nil {
			return nil, err
		}
		if p.GetInt("noop") != 0 {
			continue
		}
		return p, nil
	}
	return nil, errors.New("softether: peer sent nothing but noop")
}

// maxNoopPerSession bounds the loop above, as MAX_NOOP_PER_SESSION does in the
// reference. Without a bound a peer holds the connection open forever by
// answering every request with a noop, which costs it nothing.
const maxNoopPerSession = 16

// readHTTPBody reads one request or response and returns its body.
func readHTTPBody(br *bufio.Reader, isServer bool) ([]byte, error) {
	var body io.ReadCloser
	var length int64

	if isServer {
		req, err := http.ReadRequest(br)
		if err != nil {
			return nil, err
		}
		if req.URL.Path != httpVPNTarget {
			_ = req.Body.Close()
			return nil, fmt.Errorf("softether: control POST to %q, want %q", req.URL.Path, httpVPNTarget)
		}
		body, length = req.Body, req.ContentLength
	} else {
		resp, err := http.ReadResponse(br, nil)
		if err != nil {
			return nil, err
		}
		if resp.StatusCode != http.StatusOK {
			_ = resp.Body.Close()
			return nil, fmt.Errorf("%w: %s", errBadStatus, resp.Status)
		}
		body, length = resp.Body, resp.ContentLength
	}
	defer func() { _ = body.Close() }()

	if length > maxHTTPPackSize {
		return nil, fmt.Errorf("%w: %d octets", errPackTooLarge, length)
	}
	// LimitReader even when Content-Length looked sane: a chunked body reports
	// -1 and would otherwise be unbounded.
	return io.ReadAll(io.LimitReader(body, maxHTTPPackSize))
}

// addDummyValue appends the random-length "pencore" element that
// CreateDummyValue puts on every PACK crossing HTTP.
//
// Its purpose is length obfuscation: without it the login exchange is a
// sequence of fixed-size TLS records, which is a fingerprint. Emitting it is
// not required for a peer to parse us -- PACK is self-describing and an
// unknown element is skipped -- but a veepin connection that omitted it would
// stand out from every other SoftEther connection by exactly the property the
// element exists to hide.
func (p *Pack) addDummyValue() {
	var b [2]byte
	if _, err := rand.Read(b[:]); err != nil {
		return // padding is best-effort; a dry pool must not fail a login
	}
	n := int(binary.BigEndian.Uint16(b[:])) % httpPackRandSizeMax
	pad := make([]byte, n)
	if _, err := rand.Read(pad); err != nil {
		return
	}
	p.Add("pencore", TypeData, DataValue(pad))
}
