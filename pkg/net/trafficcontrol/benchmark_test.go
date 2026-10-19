package trafficcontrol

import (
	"testing"
	"time"
)

func BenchmarkFairQueuePushPop(b *testing.B) {
	for _,flows:=range []int{1,16,256} {
		b.Run("flows="+itoa(flows),func(b *testing.B){
			q:=NewFairQueue[int](FairConfig{MaxPackets:4096,MaxBytes:16<<20,Quantum:1514})
			now:=time.Now()
			b.ReportAllocs()
			b.ResetTimer()
			for i:=0;i<b.N;i++ {
				if !q.Push(uint64(i%flows),1400,i,now){b.Fatal("capacity")}
				_,ok,drops:=q.Pop(now)
				if !ok||len(drops)!=0{b.Fatal("dequeue")}
			}
		})
	}
}
func BenchmarkGovernorSession(b *testing.B) {
	g:=NewGovernor(Limits{MaxSessions:65536},nil)
	b.ReportAllocs()
	for i:=0;i<b.N;i++{l,ok:=g.AcquireSession();if !ok {b.Fatal("limit")};l.Release()}
}
func BenchmarkGovernorPacketAdmit(b *testing.B) {
	g:=NewGovernor(Limits{PacketsPerSec:1000000000,PacketBurst:100000000},nil)
	now:=time.Now()
	b.ReportAllocs()
	for i:=0;i<b.N;i++{if !g.AdmitPacket(now){b.Fatal("rate limit")}}
}
func itoa(n int) string {
	if n==0{return "0"}
	var b [20]byte
	p:=len(b)
	for n>0 {p--;b[p]=byte(n%10)+'0';n/=10}
	return string(b[p:])
}
