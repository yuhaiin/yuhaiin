package krunlet

import (
	"bytes"
	"encoding/binary"
	"io"
	"net"
	"net/netip"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
)

type testHandler struct{
	stream chan *netapi.StreamMeta
	packet chan *netapi.Packet
}
func (h *testHandler) HandleStream(s *netapi.StreamMeta) { h.stream <- s; _,_=s.Src.Write([]byte("ok")) }
func (h *testHandler) HandlePacket(p *netapi.Packet) {
	h.packet <- p
	_,_ = p.WriteBack(append([]byte("reply:"),p.GetPayload()...),p.Src())
}
func (h *testHandler) HandlePing(*netapi.PingMeta){}

func wireRequest(proto, family byte, source, dest string, srcPort,dstPort uint16) []byte {
	src:=netip.MustParseAddr(source)
	dst:=netip.MustParseAddr(dest)
	b:=make([]byte,10)
	copy(b,"KRN1")
	b[4],b[5]=proto,family
	binary.BigEndian.PutUint16(b[6:8],srcPort)
	binary.BigEndian.PutUint16(b[8:10],dstPort)
	b=append(b,src.AsSlice()...)
	return append(b,dst.AsSlice()...)
}

func TestKrunletInboundTCPIPv4IPv6(t *testing.T) {
	for _,tc:=range []struct{family byte;src,dst string}{
		{4,"192.168.127.2","1.1.1.1"},
		{6,"fd42:6b72:756e::2","2606:4700:4700::1111"},
	}{
		t.Run(tc.dst,func(t *testing.T){
			h:=&testHandler{stream:make(chan *netapi.StreamMeta,1)}
			path:=filepath.Join(t.TempDir(),"inbound.sock")
			s,err:=NewServer(path,h)
			if err!=nil {t.Fatal(err)}
			defer s.Close()
			conn,err:=net.Dial("unix",path)
			if err!=nil {t.Fatal(err)}
			defer conn.Close()
			_ = conn.SetDeadline(time.Now().Add(3*time.Second))
			if err:=writeAll(conn,wireRequest(protocolTCP,tc.family,tc.src,tc.dst,32100,443));err!=nil {t.Fatal(err)}
			var out [2]byte
			if _,err:=io.ReadFull(conn,out[:]);err!=nil {t.Fatal(err)}
			if string(out[:])!="ok" {t.Fatalf("got %q",out)}
			select {
			case stream:=<-h.stream:
				if stream.Address.Hostname()!=tc.dst||stream.Address.Port()!=443{
					t.Errorf("unexpected stream destination %s",stream.Address)
				}
			default:t.Fatal("handler missing stream")
			}
		})
	}
}

func TestKrunletInboundUDPDatagrams(t *testing.T) {
	h:=&testHandler{packet:make(chan *netapi.Packet,3)}
	path:=filepath.Join(t.TempDir(),"inbound.sock")
	s,err:=NewServer(path,h)
	if err!=nil {t.Fatal(err)}
	defer s.Close()
	conn,err:=net.Dial("unix",path)
	if err!=nil {t.Fatal(err)}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(3*time.Second))
	if err:=writeAll(conn,wireRequest(protocolUDP,6,"fd42:6b72:756e::2","2606:4700:4700::1111",44444,53));err!=nil {t.Fatal(err)}
	for _,msg:=range [][]byte{[]byte("abc"),[]byte("next")} {
		var hdr [2]byte
		binary.BigEndian.PutUint16(hdr[:],uint16(len(msg)))
		if err:=writeAll(conn,hdr[:]);err!=nil {t.Fatal(err)}
		if err:=writeAll(conn,msg);err!=nil {t.Fatal(err)}
		var resHeader [2]byte
		if _,err:=io.ReadFull(conn,resHeader[:]);err!=nil {t.Fatal(err)}
		resp:=make([]byte,int(binary.BigEndian.Uint16(resHeader[:])))
		if _,err:=io.ReadFull(conn,resp);err!=nil {t.Fatal(err)}
		if !bytes.Equal(resp,append([]byte("reply:"),msg...)) {t.Fatalf("got %q",resp)}
		select {case p:=<-h.packet:if p.Dst().Port()!=53 {t.Fatal("wrong udp port")};default:t.Fatal("missing packet")}
	}
}

func TestKrunletInboundRejectsMalformedHeader(t *testing.T) {
	tests:=[][]byte{
		[]byte("FAIL"),
		wireRequest(3,4,"127.0.0.1","1.1.1.1",10000,443),
		wireRequest(1,4,"127.0.0.1","1.1.1.1",10000,0),
	}
	for _,in:=range tests{
		_,err:=readRequest(bytes.NewReader(in))
		if err==nil {t.Fatalf("accepted invalid header %x",in)}
	}
}

func TestKrunletInboundExclusiveSocketAndClose(t *testing.T) {
	path:=filepath.Join(t.TempDir(),"inbound.sock")
	h:=&testHandler{stream:make(chan *netapi.StreamMeta,1)}
	server,err:=NewServer(path,h)
	if err!=nil {t.Fatal(err)}
	_,err=NewServer(path,h)
	if err==nil {t.Fatal("second listener replaced first")}
	conn,err:=net.Dial("unix",path)
	if err!=nil {t.Fatal(err)}
	var wg sync.WaitGroup
	wg.Add(1)
	go func(){defer wg.Done();defer conn.Close();var buf [1]byte;_,_=conn.Read(buf[:])}()
	if err:=server.Close();err!=nil {t.Fatal(err)}
	wg.Wait()
}
