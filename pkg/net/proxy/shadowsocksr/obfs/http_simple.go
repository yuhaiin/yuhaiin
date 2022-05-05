package obfs

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net"
	"strings"

	ssr "github.com/Asutorufa/yuhaiin/pkg/net/proxy/shadowsocksr/utils"
	"github.com/Asutorufa/yuhaiin/pkg/net/utils"
)

var (
	requestPath = []string{
		"", "",
		"login.php?redir=", "",
		"register.php?code=", "",
		"?keyword=", "",
		"search?src=typd&q=", "&lang=en",
		"s?ie=utf-8&f=8&rsv_bp=1&rsv_idx=1&ch=&bar=&wd=", "&rn=",
		"post.php?id=", "&goto=view.php",
	}
	requestUserAgent = []string{
		"Mozilla/5.0 (Windows NT 6.3; WOW64; rv:40.0) Gecko/20100101 Firefox/40.0",
		"Mozilla/5.0 (Windows NT 6.3; WOW64; rv:40.0) Gecko/20100101 Firefox/44.0",
		"Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/41.0.2228.0 Safari/537.36",
		"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/535.11 (KHTML, like Gecko) Ubuntu/11.10 Chromium/27.0.1453.93 Chrome/27.0.1453.93 Safari/537.36",
		"Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:35.0) Gecko/20100101 Firefox/35.0",
		"Mozilla/5.0 (compatible; WOW64; MSIE 10.0; Windows NT 6.2)",
		"Mozilla/5.0 (Windows; U; Windows NT 6.1; en-US) AppleWebKit/533.20.25 (KHTML, like Gecko) Version/5.0.4 Safari/533.20.27",
		"Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.3; Trident/7.0; .NET4.0E; .NET4.0C)",
		"Mozilla/5.0 (Windows NT 6.3; Trident/7.0; rv:11.0) like Gecko",
		"Mozilla/5.0 (Linux; Android 4.4; Nexus 5 Build/BuildID) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/30.0.0.0 Mobile Safari/537.36",
		"Mozilla/5.0 (iPad; CPU OS 5_0 like Mac OS X) AppleWebKit/534.46 (KHTML, like Gecko) Version/5.1 Mobile/9A334 Safari/7534.48.3",
		"Mozilla/5.0 (iPhone; CPU iPhone OS 5_0 like Mac OS X) AppleWebKit/534.46 (KHTML, like Gecko) Version/5.1 Mobile/9A334 Safari/7534.48.3",
	}
)

// HttpSimple http_simple obfs encapsulate
type httpSimplePost struct {
	ssr.ObfsInfo
	rawTransSent     bool
	rawTransReceived bool
	userAgentIndex   int
	methodGet        bool // true for get, false for post

	buf, wbuf []byte
	net.Conn

	param simpleParam
}

func init() {
	register("http_simple", newHttpSimple)
}

// newHttpSimple create a http_simple object
func newHttpSimple(conn net.Conn, info ssr.ObfsInfo) IObfs {
	t := &httpSimplePost{
		userAgentIndex: rand.Intn(len(requestUserAgent)),
		methodGet:      true,
		Conn:           conn,
		ObfsInfo:       info,
		param:          simpleParam{},
		wbuf:           utils.GetBytes(2048),
	}

	t.param.parse(t.Param)
	return t
}

func (t *httpSimplePost) boundary() (ret string) {
	set := "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
	for i := 0; i < 32; i++ {
		ret = fmt.Sprintf("%s%c", ret, set[rand.Intn(len(set))])
	}
	return
}

func (t *httpSimplePost) data2URLEncode(data []byte) (ret string) {
	for i := 0; i < len(data); i++ {
		ret = fmt.Sprintf("%s%%%s", ret, hex.EncodeToString([]byte{data[i]}))
	}
	return
}

type simpleParam struct {
	customHead string
	hosts      []string
}

func (s *simpleParam) parse(param string) {
	if len(param) == 0 {
		return
	}

	customHeads := strings.Split(param, "#")
	if len(customHeads) > 1 {
		s.customHead = strings.Replace(customHeads[1], "\\n", "\r\n", -1)
		param = customHeads[0]
	}

	s.hosts = strings.Split(param, ",")
}

func (s *simpleParam) getRandHost(host string) string {
	if len(s.hosts) == 0 {
		return host
	}
	return s.hosts[rand.Intn(len(s.hosts))]
}

func (t *httpSimplePost) encode(data []byte) []byte {
	if t.rawTransSent {
		return data
	}

	dataLength := len(data)
	headSize := t.IVSize + 30
	if dataLength-headSize > 64 {
		headSize = headSize + rand.Intn(64)
	} else {
		headSize = dataLength
	}

	buf := utils.GetBuffer()
	defer utils.PutBuffer(buf)

	if t.methodGet {
		buf.WriteString("GET /")
	} else {
		buf.WriteString("POST /")
	}

	randPathIndex := rand.Intn(len(requestPath)/2) * 2

	buf.WriteString(requestPath[randPathIndex])
	buf.WriteString(t.data2URLEncode(data[:headSize]))
	buf.WriteString(requestPath[randPathIndex+1])
	buf.WriteString("HTTP/1.1\r\n")
	buf.WriteString(fmt.Sprintf("Host: %s:%d\r\n", t.param.getRandHost(t.Host), t.Port))

	if len(t.param.customHead) > 0 {
		buf.WriteString(t.param.customHead)
		buf.WriteString("\r\n\r\n")
	} else {
		buf.WriteString(fmt.Sprintf("User-Agent: %s\r\n", requestUserAgent[t.userAgentIndex]))
		buf.WriteString("Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n")
		buf.WriteString("Accept-Language: en-US,en;q=0.8\r\n")
		buf.WriteString("Accept-Encoding: gzip, deflate\r\n")
		if !t.methodGet {
			buf.WriteString(fmt.Sprintf("Content-Type: multipart/form-data; boundary=%s\r\n", t.boundary()))
		}
		buf.WriteString("DNT: 1\r\n")
		buf.WriteString("Connection: keep-alive\r\n")
		buf.WriteString("\r\n")
	}
	buf.Write(data[headSize:])

	t.rawTransSent = true

	return buf.Bytes()
}

func (t *httpSimplePost) Read(b []byte) (int, error) {
	if t.buf != nil {
		n := copy(b, t.buf)
		if n == len(t.buf) {
			t.buf = nil
		} else {
			t.buf = t.buf[n:]
		}
		return n, nil
	}

	if t.rawTransReceived {
		return t.Conn.Read(b)
	}

	buf := utils.GetBytes(utils.DefaultSize)
	defer utils.PutBytes(buf)

	n, err := t.Conn.Read(buf)
	if err != nil {
		return n, fmt.Errorf("read http simple header failed: %w", err)
	}

	pos := bytes.Index(buf[:n], []byte("\r\n\r\n"))
	if pos == -1 {
		return 0, io.EOF
	}
	pos = pos + 4

	nn := copy(b, buf[pos:n])
	if n-pos-4 > nn {
		t.buf = append(t.buf, buf[pos+nn:n]...)
	}

	t.rawTransReceived = true

	return nn, nil
}

func (t *httpSimplePost) ReadFrom(r io.Reader) (int64, error) {
	n := int64(0)
	for {
		nr, er := r.Read(t.wbuf)
		n += int64(nr)

		_, err := t.Write(t.wbuf[:nr])
		if err != nil {
			return n, err
		}
		if er != nil {
			if errors.Is(er, io.EOF) {
				return n, nil
			}
			return n, er
		}
	}
}

func (t *httpSimplePost) Write(b []byte) (int, error) {
	if t.rawTransSent {
		return t.Conn.Write(b)
	}

	_, err := t.Conn.Write(t.encode(b))
	return len(b), err
}

func (t *httpSimplePost) GetOverhead() int {
	return 0
}
