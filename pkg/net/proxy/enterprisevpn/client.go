package enterprisevpn

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"

	contractnode "github.com/Asutorufa/yuhaiin/pkg/contract/node"
	"github.com/Asutorufa/yuhaiin/pkg/net/dialer"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/wireguard"
	"github.com/Asutorufa/yuhaiin/pkg/register"
	"github.com/xen0bit/veepin/anyconnect"
	"github.com/xen0bit/veepin/client"
	"github.com/xen0bit/veepin/dataplane"
	"github.com/xen0bit/veepin/fortinet"
	"github.com/xen0bit/veepin/ikev2"
	"github.com/xen0bit/veepin/sstp"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
)

type Client struct {
	netapi.EmptyDispatch
	session client.Session
	bridge *packetBridge
	network *wireguard.NetTun
	tcp *dialer.HappyEyeballsv2Dialer[*gonet.TCPConn]
	once sync.Once
}
var _ netapi.Proxy=(*Client)(nil)

func init(){
	register.RegisterContractPoint("ikev2",func(c contractnode.IKEv2,up netapi.Proxy)(netapi.Proxy,error){return NewIKEv2(c,up)})
	register.RegisterContractPoint("anyconnect",func(c contractnode.AnyConnect,up netapi.Proxy)(netapi.Proxy,error){return NewAnyConnect(c,up)})
	register.RegisterContractPoint("sstp",func(c contractnode.SSTP,up netapi.Proxy)(netapi.Proxy,error){return NewSSTP(c,up)})
	register.RegisterContractPoint("fortinet",func(c contractnode.Fortinet,up netapi.Proxy)(netapi.Proxy,error){return NewFortinet(c,up)})
}

func parseGateway(input string,defaultPort int)(host string,port int,err error){
	if input==""||strings.Contains(input,"://")||strings.ContainsAny(input,"/@?#"){
		return "",0,errors.New("enterprisevpn: expected gateway host[:port], without scheme")
	}
	if h,p,e:=net.SplitHostPort(input);e==nil{
		n,e:=strconv.Atoi(p)
		if e!=nil||n<1||n>65535||h==""{return "",0,errors.New("enterprisevpn: invalid gateway port")}
		return h,n,nil
	}
	host=strings.Trim(input,"[]")
	if net.ParseIP(host)==nil&&strings.Contains(host,":"){return "",0,errors.New("enterprisevpn: invalid IPv6 or gateway")}
	if host==""{return "",0,errors.New("enterprisevpn: empty gateway")}
	return host,defaultPort,nil
}
func endpointDialer(up netapi.Proxy) func(context.Context,string,string)(net.Conn,error){
	return func(ctx context.Context, network,address string)(net.Conn,error){
		addr,err:=netapi.ParseAddress(network,address)
		if err!=nil{return nil,err}
		if up!=nil&&!register.IsZero(up){return up.Conn(ctx,addr)}
		return dialer.DialHappyEyeballsv1(ctx,addr)
	}
}
func chained(up netapi.Proxy)bool{return up!=nil&&!register.IsZero(up)}

type engineDial func(context.Context,string)(client.Session,client.Result,error)
func connect(protocol string,up netapi.Proxy,dial engineDial)(*Client,error){
	bridge:=newPacketBridge()
	var nameBytes [16]byte
	if _,err:=rand.Read(nameBytes[:]);err!=nil{return nil,err}
	tunName:="yuhaiin-"+hex.EncodeToString(nameBytes[:])
	release,err:=dataplane.RegisterVirtualTUN(tunName,bridge)
	if err!=nil{return nil,err}
	defer release()
	ctx,cancel:=context.WithTimeout(context.Background(),30*1000000000)
	defer cancel()
	sess,assigned,err:=dial(ctx,tunName)
	if err!=nil{
		_ = bridge.Close()
		return nil,fmt.Errorf("%s: %w",protocol,err)
	}
	if err:=assigned.Validate();err!=nil{
		_ =sess.Close()
		_ =bridge.Close()
		return nil,fmt.Errorf("%s: peer configuration: %w",protocol,err)
	}
	network,err:=bridge.Attach(assigned)
	if err!=nil{
		_ =sess.Close()
		_ =bridge.Close()
		return nil,err
	}
	c:=&Client{session:sess,bridge:bridge,network:network}
	c.tcp=dialer.NewHappyEyeballsv2Dialer(func(ctx context.Context,ip net.IP,port uint16)(*gonet.TCPConn,error){
		return network.DialContextTCP(ctx,&net.TCPAddr{IP:ip,Port:int(port)})
	})
	return c,nil
}

func NewAnyConnect(c contractnode.AnyConnect,up netapi.Proxy)(*Client,error){
	host,port,err:=parseGateway(c.Gateway,443);if err!=nil{return nil,err}
	if c.Username==""||c.Password==""{return nil,errors.New("anyconnect: username/password required")}
	return connect("anyconnect",up,func(ctx context.Context,tun string)(client.Session,client.Result,error){
		return anyconnect.Dial(ctx,anyconnect.Config{
			Server:host,Port:port,Username:c.Username,Password:c.Password,
			TUNName:tun,Insecure:c.InsecureSkipVerify,
			NoDTLS:c.DisableDTLS||chained(up),DialContext:endpointDialer(up),
		})
	})
}
func NewSSTP(c contractnode.SSTP,up netapi.Proxy)(*Client,error){
	host,port,err:=parseGateway(c.Gateway,443);if err!=nil{return nil,err}
	if c.Username==""||c.Password==""{return nil,errors.New("sstp: username/password required")}
	return connect("sstp",up,func(ctx context.Context,tun string)(client.Session,client.Result,error){
		return sstp.Dial(ctx,sstp.Config{
			Server:host,Port:port,Username:c.Username,Password:c.Password,
			TUNName:tun,SkipVerify:c.InsecureSkipVerify,DialContext:endpointDialer(up),
		})
	})
}
func NewIKEv2(c contractnode.IKEv2,up netapi.Proxy)(*Client,error){
	if chained(up)&&!c.TCP{return nil,errors.New("ikev2: UDP NAT-T cannot be carried by this upstream; enable RFC 8229 TCP")}
	defaultPort:=500;if c.TCP{defaultPort=4500}
	host,port,err:=parseGateway(c.Gateway,defaultPort);if err!=nil{return nil,err}
	if c.LocalID==""{return nil,errors.New("ikev2: local_id is required")}
	if c.PSK==""{return nil,errors.New("ikev2: PSK required")}
	return connect("ikev2",up,func(ctx context.Context,tun string)(client.Session,client.Result,error){
		return ikev2.Dial(ctx,ikev2.Config{
			Server:host,Port:port,PSK:c.PSK,LocalID:c.LocalID,ServerID:c.ServerID,
			EAPUser:c.Username,EAPPassword:c.Password,TCP:c.TCP,
			TUNName:tun,DialContext:endpointDialer(up),
		})
	})
}
func NewFortinet(c contractnode.Fortinet,up netapi.Proxy)(*Client,error){
	host,port,err:=parseGateway(c.Gateway,443);if err!=nil{return nil,err}
	if c.Username==""{return nil,errors.New("fortinet: username required")}
	var roots *x509.CertPool
	if c.CACertPEM!=""{
		roots,err=x509.SystemCertPool()
		if err!=nil||roots==nil{roots=x509.NewCertPool()}
		if !roots.AppendCertsFromPEM([]byte(c.CACertPEM)){return nil,errors.New("fortinet: invalid CA PEM")}
	}
	return connect("fortinet",up,func(ctx context.Context,tun string)(client.Session,client.Result,error){
		return fortinet.Dial(ctx,fortinet.Config{
			Server:host,Port:port,Username:c.Username,Password:c.Password,Realm:c.Realm,
			Token:c.Token,TOTPSecret:c.TOTPSecret,RootCAs:roots,
			Insecure:c.InsecureSkipVerify,NoDTLS:c.DisableDTLS||chained(up),
			TUNName:tun,DialContext:endpointDialer(up),
		})
	})
}
func (c *Client) Conn(ctx context.Context,addr netapi.Address)(net.Conn,error){
	conn,err:=c.tcp.DialHappyEyeballsv2(ctx,addr)
	if err!=nil{return nil,err}
	return wireguard.NewWrapGoNetTcpConn(conn),nil
}
func (c *Client) PacketConn(ctx context.Context,_ netapi.Address)(net.PacketConn,error){
	udp,err:=c.network.DialUDP(nil,nil)
	if err!=nil{return nil,err}
	return wireguard.NewWrapGoNetUdpConn(context.WithoutCancel(ctx),udp),nil
}
func (c *Client) Ping(context.Context,netapi.Address)(uint64,error){return 0,errors.ErrUnsupported}
func (c *Client) Close()error{
	var err error
	c.once.Do(func(){
		err=c.session.Close()
		_ =c.bridge.Close()
	})
	return err
}
