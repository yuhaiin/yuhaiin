package trafficcontrol

import (
	"runtime"
	"sync"
	"testing"
	"time"
)

func TestGroupedFairQueueHostIsolationFromFlowMultiplication(t *testing.T) {
	q:=NewGroupedFairQueue[int](FairConfig{MaxPackets:1024,MaxBytes:1024*1400,Quantum:1400})
	now:=time.Now()
	for i:=range 480 {
		if !q.Push(1,uint64(i%120),1400,1,now,1){t.Fatal("bulk host admission")}
	}
	for range 120 {
		if !q.Push(2,9,1400,2,now,1){t.Fatal("interactive host admission")}
	}
	var one,two int
	for range 200 {
		v,ok,drops:=q.Pop(now)
		if !ok||len(drops)>0{t.Fatalf("unexpected drop: %t %d",ok,len(drops))}
		if v==1 {one++}else if v==2{two++}else{t.Fatal("corrupt packet")}
	}
	if one<85||one>115||two<85||two>115 {
		t.Fatalf("120 parallel flows unfair against one peer: a=%d b=%d",one,two)
	}
	s:=q.Stats()
	if s.Packets!=400||s.Bytes!=400*1400||s.Flows!=2{t.Fatal(s)}
	remaining:=q.Drain()
	if len(remaining)!=400||q.Stats().Packets!=0{t.Fatal("drain lost ownership")}
}

func TestGroupedFairQueueCapsCancellationAndAQM(t *testing.T) {
	q:=NewGroupedFairQueue[int](FairConfig{MaxPackets:4,MaxBytes:2500,Quantum:1000,Target:time.Millisecond,Interval:time.Millisecond})
	now:=time.Now()
	if !q.Push(1,1,1000,1,now,1)||!q.Push(2,2,1000,2,now,1) {t.Fatal("admission")}
	if q.Push(3,3,600,3,now,1){t.Fatal("byte budget bypass")}
	if !q.Push(1,1,500,4,now,1){t.Fatal("remaining headroom")}
	if q.Push(3,3,1,5,now,1){t.Fatal("packet budget bypass")}
	s:=q.Stats()
	if s.Packets!=3||s.Bytes!=2500||s.Rejected!=2{t.Fatal(s)}
	all:=q.Drain()
	if len(all)!=3||q.Stats().Flows!=0{t.Fatal("drain error",all,q.Stats())}
}

func TestGroupedFairQueueConcurrentOwnership(t *testing.T) {
	q:=NewGroupedFairQueue[int](FairConfig{MaxPackets:1000,MaxBytes:1000*1400})
	now:=time.Now()
	var wg sync.WaitGroup
	for group:=range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i:=range 100 {
				if !q.Push(uint64(group),uint64(i%10),1400,i,now,1) {t.Error("unexpected admission rejection")}
			}
		}()
	}
	wg.Wait()
	seen:=0
	for {
		_,ok,dropped:=q.Pop(now)
		seen+=len(dropped)
		if !ok {break}
		seen++
	}
	if seen!=800||q.Stats().Packets!=0 {t.Fatalf("lost ownership: %d",seen)}
	runtime.KeepAlive(q)
}

func BenchmarkGroupedFairQueueHostIsolation(b *testing.B) {
	q:=NewGroupedFairQueue[int](FairConfig{MaxPackets:1024,MaxBytes:1024*1500,Quantum:1514})
	now:=time.Now()
	for i:=range 1024 {q.Push(uint64(i%16),uint64(i),1400,i,now,1)}
	b.ReportAllocs()
	b.SetBytes(1400)
	b.ResetTimer()
	for i:=range b.N {
		_,ok,drops:=q.Pop(now)
		if !ok||len(drops)!=0{b.Fatal("pop")}
		if !q.Push(uint64(i%16),uint64(i%512),1400,i,now,1){b.Fatal("push")}
	}
}
