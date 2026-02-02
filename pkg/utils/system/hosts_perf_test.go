package system

import (
	"fmt"
	"os"
	"sync"
	"testing"
	"time"
)

func TestRaceCondition(t *testing.T) {
	// Setup a temp hosts file
	f, err := os.CreateTemp("", "hosts")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(f.Name())
	defer f.Close()

	// Fill with some data
	f.WriteString("127.0.0.1 localhost\n")
	f.WriteString("192.168.1.1 router\n")

	// Override hostsFilePath
	originalPath := hostsFilePath
	hostsFilePath = f.Name()
	defer func() { hostsFilePath = originalPath }()

	// Force refresh initially
	expire.Store(0)

	var wg sync.WaitGroup
	start := make(chan struct{})

	// Readers
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			for j := 0; j < 100; j++ {
				addrs, _ := LookupStaticHost("router")
				if len(addrs) == 0 {
					t.Error("LookupStaticHost(router) returned empty")
					return
				}
				if addrs[0].String() != "192.168.1.1" {
					t.Errorf("LookupStaticHost(router) = %v, want 192.168.1.1", addrs[0])
				}
			}
		}()
	}

	// Writers (simulating expiration trigger)
	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			for j := 0; j < 100; j++ {
				// Force expire to 0 to trigger refresh logic
				expire.Store(0)
				addrs, _ := LookupStaticHost("localhost")
				if len(addrs) == 0 {
					t.Error("LookupStaticHost(localhost) returned empty")
					return
				}
				if addrs[0].String() != "127.0.0.1" {
					t.Errorf("LookupStaticHost(localhost) = %v, want 127.0.0.1", addrs[0])
				}
				time.Sleep(time.Millisecond)
			}
		}()
	}

	close(start)
	wg.Wait()
}

func BenchmarkLookupStaticHost(b *testing.B) {
	// Setup a large hosts file
	f, err := os.CreateTemp("", "hosts_bench")
	if err != nil {
		b.Fatal(err)
	}
	defer os.Remove(f.Name())
	defer f.Close()

	for i := 0; i < 1000; i++ {
		fmt.Fprintf(f, "192.168.0.%d host%d.local\n", i%255, i)
	}

	originalPath := hostsFilePath
	hostsFilePath = f.Name()
	defer func() { hostsFilePath = originalPath }()

	// Reset expire to force initial load
	expire.Store(0)

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			LookupStaticHost("host500.local")
		}
	})
}
