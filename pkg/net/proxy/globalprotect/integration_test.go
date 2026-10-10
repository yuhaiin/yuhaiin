package globalprotect

import (
 "bytes"
 "context"
 "encoding/pem"
 "fmt"
 "io"
 "net"
 "net/http"
 "net/http/httptest"
 "net/netip"
 "strings"
 "sync"
 "testing"
 "time"

 "github.com/Asutorufa/yuhaiin/pkg/net/netapi"
 "github.com/Asutorufa/yuhaiin/pkg/net/proxy/wireguard"
 "github.com/tailscale/wireguard-go/tun"
)

// TestGatewayEndToEndTCPUDP starts a full in-process fake HTTPS gateway.
// Unlike the XML fixture tests it drives the public GlobalProtect client
// through prelogin -> login -> config -> TLS tunnel -> gVisor TCP/UDP echo.
// It is NOT a compatibility test against a real PAN-OS server.
func TestGatewayEndToEndTCPUDP(t *testing.T) {
 const (
  serverIP = "10.203.0.1"
  clientIP = "10.203.0.2"
  tcpPort = 23456
  udpPort = 23457
  mtu = 1300
 )
 stack, err := wireguard.CreateNetTUN([]netip.Prefix{netip.MustParsePrefix(serverIP + "/32")}, mtu)
 if err != nil { t.Fatal(err) }

 tcpListener, err := stack.ListenTCP(&net.TCPAddr{IP: net.ParseIP(serverIP), Port:tcpPort})
 if err != nil { _ = stack.Close(); t.Fatal(err) }
 udpSocket, err := stack.DialUDP(&net.UDPAddr{IP:net.ParseIP(serverIP),Port:udpPort}, nil)
 if err != nil { _ = tcpListener.Close(); _ = stack.Close(); t.Fatal(err) }

 go func() {
  for {
   conn, err := tcpListener.Accept()
   if err != nil { return }
   go func() {
    defer conn.Close()
    _,_ = io.Copy(conn,conn)
   }()
  }
 }()
 go func() {
  buf := make([]byte,mtu)
  for {
   n,src,err:=udpSocket.ReadFrom(buf)
   if err!=nil {return}
   if _,err=udpSocket.WriteTo(buf[:n],src);err!=nil {return}
  }
 }()

 var (
  mu sync.Mutex
  authenticated bool
  sawLogout bool
 )
 handler := http.HandlerFunc(func(w http.ResponseWriter,r *http.Request) {
  switch r.URL.Path {
  case "/ssl-vpn/prelogin.esp":
   _,_ = io.WriteString(w,"<prelogin-response><status>Success</status><saml-auth-status>0</saml-auth-status></prelogin-response>")
  case "/ssl-vpn/login.esp":
   _ = r.ParseForm()
   if r.Form.Get("user")!="alice" || r.Form.Get("passwd")!="secret" {
    http.Error(w,"bad credentials",http.StatusUnauthorized)
    return
   }
   mu.Lock()
   authenticated=true
   mu.Unlock()
   _,_ = io.WriteString(w,"<jnlp><application-desc>"+
    "<argument>(null)</argument><argument>test-cookie</argument>"+
    "<argument>unused</argument><argument>test-gateway</argument>"+
    "<argument>alice</argument><argument>LDAP</argument>"+
    "<argument>vsys1</argument><argument>test-domain</argument>"+
    "</application-desc></jnlp>")
  case "/ssl-vpn/getconfig.esp":
   _=r.ParseForm()
   if r.Form.Get("authcookie")!="test-cookie" {http.Error(w,"no cookie",http.StatusForbidden);return}
   _,_ = fmt.Fprintf(w,`<response status="success"><need-tunnel>yes</need-tunnel>
<ip-address>%s</ip-address><netmask>255.255.255.255</netmask>
<ssl-tunnel-url>/ssl-tunnel-connect.sslvpn</ssl-tunnel-url><mtu>%d</mtu>
<timeout>3600</timeout></response>`,clientIP,mtu)
  case "/ssl-vpn/logout.esp":
   mu.Lock()
   sawLogout=true
   mu.Unlock()
   _,_ = io.WriteString(w,"<response status=\"success\"/>")
  case "/ssl-tunnel-connect.sslvpn":
   if r.URL.Query().Get("authcookie")!="test-cookie" {http.Error(w,"no cookie",http.StatusForbidden);return}
   hijack,ok:=w.(http.Hijacker)
   if !ok {http.Error(w,"no hijacker",http.StatusInternalServerError);return}
   conn,_,err:=hijack.Hijack()
   if err!=nil {return}
   defer conn.Close()
   if _,err:=io.WriteString(conn,"START_TUNNEL");err!=nil {return}
   var writeMu sync.Mutex
   writeFrame := func(frame []byte) error {
    writeMu.Lock()
    defer writeMu.Unlock()
    _,err:=conn.Write(frame)
    return err
   }
   // Drain outgoing packets from the server-side gVisor stack and
   // send them to the client's TLS transport.
   go func() {
    slab:=make([]byte,mtu+2*tun.ReadPacketSpacing)
    desc:=make([]tun.ReadPacket,1)
    for {
     n,err:=stack.Read(slab,desc)
     if err!=nil {return}
     for _,p:=range desc[:n] {
      if p.Offset<0 || p.Size<=0 || p.Offset+p.Size>len(slab) {return}
      frame,err:=encodeFrame(slab[p.Offset:p.Offset+p.Size])
      if err!=nil || writeFrame(frame)!=nil {return}
     }
    }
   }()
   for {
    packet,dpd,err:=readFrame(conn,mtu)
    if err!=nil {return}
    if dpd {
     if writeFrame(dpdFrame())!=nil {return}
     continue
    }
    if _,err:=stack.Write([][]byte{packet},0);err!=nil {return}
   }
  default:
   http.NotFound(w,r)
  }
 })
 server:=httptest.NewTLSServer(handler)
 t.Cleanup(func() {
  server.CloseClientConnections()
  _ = tcpListener.Close()
  _ = udpSocket.Close()
  _ = stack.Close()
  server.Close()
 })
 gateway:=strings.TrimPrefix(server.URL,"https://")
 ca:=pem.EncodeToMemory(&pem.Block{Type:"CERTIFICATE",Bytes:server.Certificate().Raw})
 proxy,err:=NewClient(Config{
  Gateway:gateway, Username:"alice",Password:"secret",
  CACertPEM:string(ca), MTU:mtu,
 },nil)
 if err!=nil {t.Fatal(err)}
 defer proxy.Close()

 ctx,cancel:=context.WithTimeout(context.Background(),10*time.Second)
 defer cancel()
 tcpAddr,err:=netapi.ParseAddress("tcp",fmt.Sprintf("%s:%d",serverIP,tcpPort))
 if err!=nil {t.Fatal(err)}
 tcpConn,err:=proxy.Conn(ctx,tcpAddr)
 if err!=nil {t.Fatal(err)}
 defer tcpConn.Close()
 _ = tcpConn.SetDeadline(time.Now().Add(5*time.Second))
 data:=[]byte("globalprotect-tcp-e2e")
 if _,err:=tcpConn.Write(data);err!=nil {t.Fatal(err)}
 echoed:=make([]byte,len(data))
 if _,err:=io.ReadFull(tcpConn,echoed);err!=nil {t.Fatal(err)}
 if !bytes.Equal(data,echoed) {t.Fatalf("TCP echo mismatch: %q",echoed)}

 udpAddr,err:=netapi.ParseAddress("udp",fmt.Sprintf("%s:%d",serverIP,udpPort))
 if err!=nil {t.Fatal(err)}
 packetConn,err:=proxy.PacketConn(ctx,udpAddr)
 if err!=nil {t.Fatal(err)}
 defer packetConn.Close()
 _=packetConn.SetDeadline(time.Now().Add(5*time.Second))
 udpPayload:=[]byte("globalprotect-udp-e2e")
 if _,err:=packetConn.WriteTo(udpPayload,&net.UDPAddr{IP:net.ParseIP(serverIP),Port:udpPort});err!=nil {t.Fatal(err)}
 buf:=make([]byte,128)
 n,_,err:=packetConn.ReadFrom(buf)
 if err!=nil {t.Fatal(err)}
 if !bytes.Equal(buf[:n],udpPayload) {t.Fatalf("UDP echo mismatch: %q",buf[:n])}

 mu.Lock()
 wasAuthenticated:=authenticated
 mu.Unlock()
 if !wasAuthenticated {t.Fatal("gateway authentication was bypassed")}
 if err:=proxy.Close();err!=nil {t.Fatal(err)}
 mu.Lock()
 didLogout:=sawLogout
 mu.Unlock()
 if !didLogout {t.Fatal("gateway did not receive logout")}
 if _,err:=proxy.Conn(ctx,tcpAddr);err==nil {t.Fatal("closed proxy accepted TCP dial")}
}
