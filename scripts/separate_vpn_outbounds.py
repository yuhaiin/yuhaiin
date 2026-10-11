#!/usr/bin/env python3
"""One-shot layout migration: separate VPN outbounds, no enterprisevpn or internal/engine.

Source: veepin MIT, pinned commit 810e017596c0b5b55bc0da563929bde13a6b201d.
After applying, this script and its temporary CI runner are deleted.
"""
from __future__ import annotations
import pathlib
import re
import shutil
import subprocess

ROOT = pathlib.Path(__file__).resolve().parents[1]
BASE = ROOT / "pkg/net/proxy"
OLD = BASE / "enterprisevpn"
SOURCE = OLD / "internal/engine"
assert SOURCE.is_dir(), "Expected pre-migration client code"

IMPORT_BASE = "github.com/Asutorufa/yuhaiin/pkg/net/proxy"
OLD_IMPORT = IMPORT_BASE + "/enterprisevpn/internal/engine"
SHARED = IMPORT_BASE + "/vpnkit"
MAPPING = {
    "internal/ikev2/": "ikev2/",
    "internal/anyconnect/": "anyconnect/protocol/",
    "internal/fortinet/": "fortinet/protocol/",
    "internal/sstp/": "sstp/",
    "internal/": "vpnkit/",
    "client/": "vpnkit/session/",
    "dataplane/": "vpnkit/dataplane/",
    "anyconnect/": "anyconnect/",
    "fortinet/": "fortinet/",
    "ikev2/": "ikev2/",
    "sstp/": "sstp/",
}
# Protocol engine source is kept in its owning package. Generic crypto, PPP,
# packet transport and session helpers are under vpnkit, outside any internal dir.
def dest(rel: str) -> str:
    for before, after in MAPPING.items():
        if rel.startswith(before):
            return after + rel[len(before):]
    raise RuntimeError(f"Unmapped source {rel}")

PKG_PATH_MAP = {}
for f in SOURCE.rglob("*.go"):
    rel=f.relative_to(SOURCE).as_posix()
    before=rel.rsplit("/",1)[0]
    after=dest(rel).rsplit("/",1)[0]
    PKG_PATH_MAP[OLD_IMPORT+"/"+before] = IMPORT_BASE+"/"+after

def rewrite_imports(src: str) -> str:
    for key in sorted(PKG_PATH_MAP,key=len,reverse=True):
        src=src.replace('"'+key+'"','"'+PKG_PATH_MAP[key]+'"')
    return src

skip = {"client/opts.go","client/variant.go",
        "anyconnect/opts.go","fortinet/opts.go","ikev2/opts.go","sstp/opts.go"}
for f in sorted(SOURCE.rglob("*.go")):
    rel=f.relative_to(SOURCE).as_posix()
    if rel in skip:
        continue
    out=BASE/dest(rel)
    if out.exists():
        raise RuntimeError(f"Refusing overwrite: {out}")
    src=f.read_text()
    if rel=="client/client.go":
        src=src.replace("parse, ok := lookupParse(protocol)",
                        "mu.RLock()\n\tparse, ok := protocols[protocol]\n\tmu.RUnlock()")
        src=src.replace("ErrUnknownProtocol, protocol, AllProtocols())",
                        "ErrUnknownProtocol, protocol, Protocols())")
    if rel=="internal/dtls/conn.go":
        start=src.index("// Server performs a DTLS handshake")
        end=src.index("func (c *Conn) mtu()",start)
        src=src[:start]+src[end:]
    if rel=="internal/ikev2/ike/client.go":
        # The non-PQ client shares no host routes or server processes.
        pass
    out.parent.mkdir(parents=True,exist_ok=True)
    out.write_text(rewrite_imports(src))

# Route trie is an in-memory data structure used by the packet pump, not a
# kernel routing operation. The earlier pruning omitted this required file.
# It is checked in separately from the pinned upstream routes.go.
routes = BASE / "vpnkit/dataplane/routes.go"
assert routes.is_file(), "Missing in-memory dataplane route trie"

# Real shared packet bridge (gVisor TUN), with no single enterprise proxy.
bridge=(OLD/"bridge.go").read_text()
bridge=bridge.replace("package enterprisevpn","package vpnkit",1)
(BASE/"vpnkit/bridge.go").write_text(bridge)
shutil.copy2(SOURCE/"LICENSE",BASE/"vpnkit/LICENSE")
origin=(SOURCE/"UPSTREAM.md").read_text()
for proto in ("ikev2","anyconnect","sstp","fortinet"):
    shutil.copy2(SOURCE/"LICENSE",BASE/proto/"LICENSE")
    (BASE/proto/"UPSTREAM.md").write_text(
        f"# {proto} client protocol\n\nSelected and adapted from "
        "[xen0bit/veepin](https://github.com/xen0bit/veepin)"
        " at `810e017596c0b5b55bc0da563929bde13a6b201d`.\n"
        "MIT licensed. See LICENSE. Only the client implementation is included.\n"
    )
(BASE/"vpnkit/UPSTREAM.md").write_text(origin.replace("Enterprise VPN protocol engines","Shared VPN client infrastructure"))

(BASE/"vpnkit/proxy.go").write_text("""package vpnkit

import (
    "context"
    "crypto/rand"
    "encoding/hex"
    "errors"
    "fmt"
    "net"
    "strconv"
    "strings"
    "sync"
    "time"

    "github.com/Asutorufa/yuhaiin/pkg/net/dialer"
    "github.com/Asutorufa/yuhaiin/pkg/net/netapi"
    "github.com/Asutorufa/yuhaiin/pkg/net/proxy/vpnkit/dataplane"
    vpnclient "github.com/Asutorufa/yuhaiin/pkg/net/proxy/vpnkit/session"
    "github.com/Asutorufa/yuhaiin/pkg/net/proxy/wireguard"
    "github.com/Asutorufa/yuhaiin/pkg/register"
    "gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
)

// Client only contains protocol-independent outbound IP packet plumbing.
// Each VPN protocol owns its own registration, credentials and authentication.
type Client struct {
    netapi.EmptyDispatch
    session vpnclient.Session
    bridge *packetBridge
    network *wireguard.NetTun
    tcp *dialer.HappyEyeballsv2Dialer[*gonet.TCPConn]
    once sync.Once
}
var _ netapi.Proxy = (*Client)(nil)
type DialSession func(context.Context, string) (vpnclient.Session, vpnclient.Result, error)

func NewOutbound(name string,dial DialSession)(*Client,error){
    bridge:=newPacketBridge()
    var id [16]byte
    if _,err:=rand.Read(id[:]);err!=nil{return nil,err}
    tunName:="yuhaiin-"+hex.EncodeToString(id[:])
    release,err:=dataplane.RegisterVirtualTUN(tunName,bridge)
    if err!=nil{return nil,err}
    defer release()
    ctx,cancel:=context.WithTimeout(context.Background(),30*time.Second)
    defer cancel()
    session,assigned,err:=dial(ctx,tunName)
    if err!=nil{_ =bridge.Close();return nil,fmt.Errorf("%s: %w",name,err)}
    if err:=assigned.Validate();err!=nil{
        _ =session.Close();_ =bridge.Close()
        return nil,fmt.Errorf("%s: invalid assigned tunnel configuration: %w",name,err)
    }
    network,err:=bridge.Attach(assigned)
    if err!=nil{_ =session.Close();_ =bridge.Close();return nil,err}
    c:=&Client{session:session,bridge:bridge,network:network}
    c.tcp=dialer.NewHappyEyeballsv2Dialer(func(ctx context.Context,ip net.IP,port uint16)(*gonet.TCPConn,error){
        return network.DialContextTCP(ctx,&net.TCPAddr{IP:ip,Port:int(port)})
    })
    return c,nil
}
func ParseGateway(s string,defaultPort int)(string,int,error){
    if s=="" || strings.Contains(s,"://") || strings.ContainsAny(s,"/@?#"){
        return "",0,errors.New("VPN gateway must be host[:port], without URL scheme")
    }
    if host,port,e:=net.SplitHostPort(s);e==nil{
        p,err:=strconv.Atoi(port)
        if err!=nil||p<=0||p>65535||host==""{return "",0,errors.New("invalid VPN gateway port")}
        return host,p,nil
    }
    host:=strings.Trim(s,"[]")
    if net.ParseIP(host)==nil && strings.Contains(host,":"){return "",0,errors.New("invalid VPN gateway")}
    if host==""{return "",0,errors.New("empty VPN gateway")}
    return host,defaultPort,nil
}
func IsChained(up netapi.Proxy)bool{return up!=nil&&!register.IsZero(up)}
func EndpointDialer(up netapi.Proxy)func(context.Context,string,string)(net.Conn,error){
    return func(ctx context.Context, network, host string)(net.Conn,error){
        address,err:=netapi.ParseAddress(network,host)
        if err!=nil{return nil,err}
        if IsChained(up){return up.Conn(ctx,address)}
        return dialer.DialHappyEyeballsv1(ctx,address)
    }
}
func (c *Client)Conn(ctx context.Context,addr netapi.Address)(net.Conn,error){
    conn,err:=c.tcp.DialHappyEyeballsv2(ctx,addr)
    if err!=nil{return nil,err}
    return wireguard.NewWrapGoNetTcpConn(conn),nil
}
func (c *Client)PacketConn(ctx context.Context,_ netapi.Address)(net.PacketConn,error){
    udp,err:=c.network.DialUDP(nil,nil)
    if err!=nil{return nil,err}
    return wireguard.NewWrapGoNetUdpConn(context.WithoutCancel(ctx),udp),nil
}
func (c *Client)Ping(context.Context,netapi.Address)(uint64,error){return 0,errors.ErrUnsupported}
func (c *Client)Close()error{
    var err error
    c.once.Do(func(){err=c.session.Close();_ =c.bridge.Close()})
    return err
}
""")

# Each protocol owns an independent yuhaiin node registration. No catch-all
# enterprisevpn package, global proxy selector or generic protocol dispatcher.
outbounds={
"ikev2":"""package ikev2

import (
    "context"
    "errors"
    "github.com/Asutorufa/yuhaiin/pkg/contract/node"
    "github.com/Asutorufa/yuhaiin/pkg/net/netapi"
    "github.com/Asutorufa/yuhaiin/pkg/net/proxy/vpnkit"
    "github.com/Asutorufa/yuhaiin/pkg/register"
)
func init(){register.RegisterContractPoint("ikev2",func(c node.IKEv2,up netapi.Proxy)(netapi.Proxy,error){return NewOutbound(c,up)})}
func NewOutbound(c node.IKEv2,up netapi.Proxy)(netapi.Proxy,error){
    if vpnkit.IsChained(up)&&!c.TCP{return nil,errors.New("ikev2: UDP NAT-T through upstream is unsupported; select RFC 8229 TCP encapsulation")}
    port:=500;if c.TCP{port=4500}
    host,p,err:=vpnkit.ParseGateway(c.Gateway,port);if err!=nil{return nil,err}
    if c.LocalID==""||c.PSK==""{return nil,errors.New("ikev2: local ID and PSK are required")}
    return vpnkit.NewOutbound("ikev2",func(ctx context.Context,tun string)(client.Session,client.Result,error){
        return Dial(ctx,Config{Server:host,Port:p,LocalID:c.LocalID,ServerID:c.ServerID,
            PSK:c.PSK,EAPUser:c.Username,EAPPassword:c.Password,TCP:c.TCP,
            TUNName:tun,DialContext:vpnkit.EndpointDialer(up)})
    })
}
""",
"anyconnect":"""package anyconnect
import (
    "context"
    "errors"
    "github.com/Asutorufa/yuhaiin/pkg/contract/node"
    "github.com/Asutorufa/yuhaiin/pkg/net/netapi"
    "github.com/Asutorufa/yuhaiin/pkg/net/proxy/vpnkit"
    "github.com/Asutorufa/yuhaiin/pkg/register"
)
func init(){register.RegisterContractPoint("anyconnect",func(c node.AnyConnect,up netapi.Proxy)(netapi.Proxy,error){return NewOutbound(c,up)})}
func NewOutbound(c node.AnyConnect,up netapi.Proxy)(netapi.Proxy,error){
    host,port,err:=vpnkit.ParseGateway(c.Gateway,443);if err!=nil{return nil,err}
    if c.Username==""||c.Password==""{return nil,errors.New("anyconnect: username/password required")}
    return vpnkit.NewOutbound("anyconnect",func(ctx context.Context,tun string)(client.Session,client.Result,error){
        return Dial(ctx,Config{Server:host,Port:port,Username:c.Username,Password:c.Password,
          TUNName:tun,Insecure:c.InsecureSkipVerify,
          NoDTLS:c.DisableDTLS||vpnkit.IsChained(up),DialContext:vpnkit.EndpointDialer(up)})
    })
}
""",
"sstp":"""package sstp
import (
    "context"
    "errors"
    "github.com/Asutorufa/yuhaiin/pkg/contract/node"
    "github.com/Asutorufa/yuhaiin/pkg/net/netapi"
    "github.com/Asutorufa/yuhaiin/pkg/net/proxy/vpnkit"
    "github.com/Asutorufa/yuhaiin/pkg/register"
)
func init(){register.RegisterContractPoint("sstp",func(c node.SSTP,up netapi.Proxy)(netapi.Proxy,error){return NewOutbound(c,up)})}
func NewOutbound(c node.SSTP,up netapi.Proxy)(netapi.Proxy,error){
    host,port,err:=vpnkit.ParseGateway(c.Gateway,443);if err!=nil{return nil,err}
    if c.Username==""||c.Password==""{return nil,errors.New("sstp: username/password required")}
    return vpnkit.NewOutbound("sstp",func(ctx context.Context,tun string)(client.Session,client.Result,error){
        return Dial(ctx,Config{Server:host,Port:port,Username:c.Username,Password:c.Password,
           TUNName:tun,SkipVerify:c.InsecureSkipVerify,DialContext:vpnkit.EndpointDialer(up)})
    })
}
""",
"fortinet":"""package fortinet
import (
    "context"
    "crypto/x509"
    "errors"
    "github.com/Asutorufa/yuhaiin/pkg/contract/node"
    "github.com/Asutorufa/yuhaiin/pkg/net/netapi"
    "github.com/Asutorufa/yuhaiin/pkg/net/proxy/vpnkit"
    "github.com/Asutorufa/yuhaiin/pkg/register"
)
func init(){register.RegisterContractPoint("fortinet",func(c node.Fortinet,up netapi.Proxy)(netapi.Proxy,error){return NewOutbound(c,up)})}
func NewOutbound(c node.Fortinet,up netapi.Proxy)(netapi.Proxy,error){
    host,port,err:=vpnkit.ParseGateway(c.Gateway,443);if err!=nil{return nil,err}
    if c.Username==""{return nil,errors.New("fortinet: username required")}
    var roots *x509.CertPool
    if c.CACertPEM!=""{
        roots,err=x509.SystemCertPool();if err!=nil||roots==nil{roots=x509.NewCertPool()}
        if !roots.AppendCertsFromPEM([]byte(c.CACertPEM)){return nil,errors.New("fortinet: invalid CA PEM")}
    }
    return vpnkit.NewOutbound("fortinet",func(ctx context.Context,tun string)(client.Session,client.Result,error){
        s,res,e:=Dial(ctx,Config{Server:host,Port:port,Username:c.Username,Password:c.Password,
            Realm:c.Realm,Token:c.Token,TOTPSecret:c.TOTPSecret,RootCAs:roots,
            Insecure:c.InsecureSkipVerify,NoDTLS:c.DisableDTLS||vpnkit.IsChained(up),
            TUNName:tun,DialContext:vpnkit.EndpointDialer(up)})
        return s,res,e
    })
}
"""
}
for proto,src in outbounds.items():
    src=src.replace('"github.com/Asutorufa/yuhaiin/pkg/net/proxy/vpnkit"','"github.com/Asutorufa/yuhaiin/pkg/net/proxy/vpnkit"\n    client "github.com/Asutorufa/yuhaiin/pkg/net/proxy/vpnkit/session"')
    (BASE/proto/"outbound.go").write_text(src)

app=ROOT/"pkg/app/app.go"
text=app.read_text()
text=text.replace('_ "github.com/Asutorufa/yuhaiin/pkg/net/proxy/enterprisevpn"',
    '_ "github.com/Asutorufa/yuhaiin/pkg/net/proxy/ikev2"\n'
    '\t_ "github.com/Asutorufa/yuhaiin/pkg/net/proxy/anyconnect"\n'
    '\t_ "github.com/Asutorufa/yuhaiin/pkg/net/proxy/sstp"\n'
    '\t_ "github.com/Asutorufa/yuhaiin/pkg/net/proxy/fortinet"')
app.write_text(text)

# The old monolithic wrapper and engine are dead after the import rewrite.
shutil.rmtree(OLD)

subprocess.run(["gofmt","-w",*[str(p) for p in (BASE/"vpnkit").rglob("*.go")],
     *[str(p) for proto in outbounds for p in (BASE/proto).rglob("*.go")],str(app)] ,check=True)
print("Moved independent VPN protocols and shared primitives; no internal/engine or enterprisevpn")
