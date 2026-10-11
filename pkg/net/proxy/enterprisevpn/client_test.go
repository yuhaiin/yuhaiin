package enterprisevpn

import (
	"context"
	"net"
	"strings"
	"testing"

	contractnode "github.com/Asutorufa/yuhaiin/pkg/contract/node"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
)
func TestGatewayParsing(t *testing.T){
	tests:=[]struct{in string;wantHost string;wantPort int}{
		{"vpn.example.com","vpn.example.com",443},
		{"vpn.example.com:444","vpn.example.com",444},
		{"[2001:db8::1]:8443","2001:db8::1",8443},
		{"2001:db8::2","2001:db8::2",443},
	}
	for _,tt:=range tests {
		h,p,err:=parseGateway(tt.in,443)
		if err!=nil||h!=tt.wantHost||p!=tt.wantPort{t.Fatalf("parse %q: %q %d %v",tt.in,h,p,err)}
	}
	for _,v:=range []string{"https://example.com","example.com/abc","host:70000","[::1]:99999",""}{
		if _,_,err:=parseGateway(v,443);err==nil{t.Errorf("accepted invalid gateway %q",v)}
	}
}
func TestIKEv2NoChainedUDPFallback(t *testing.T){
	// The actual upstream is a deliberately non-networked stub.
	up:=&rejectingProxy{}
	_,err:=NewIKEv2(contractnode.IKEv2{Gateway:"vpn.example.com",PSK:"test",LocalID:"client"},up)
	if err==nil||!strings.Contains(err.Error(),"UDP NAT-T"){t.Fatalf("unexpected: %v",err)}
}
type rejectingProxy struct{netapi.EmptyDispatch}
func (*rejectingProxy) Conn(context.Context,netapi.Address)(net.Conn,error){return nil,net.ErrClosed}
func (*rejectingProxy) PacketConn(context.Context,netapi.Address)(net.PacketConn,error){return nil,net.ErrClosed}
func (*rejectingProxy) Ping(context.Context,netapi.Address)(uint64,error){return 0,net.ErrClosed}
func (*rejectingProxy) Close()error{return nil}
