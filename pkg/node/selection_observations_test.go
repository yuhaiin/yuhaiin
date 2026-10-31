package node

import (
	"fmt"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	contract "github.com/Asutorufa/yuhaiin/pkg/contract/node"
)

func TestSelectionObservationsFreezeHistoryAndKeepPublicCopiesIndependent(t *testing.T) {
	c := new(nodeCounters)
	for range 64 {
		c.remoteEvidence(true, contract.HealthSample{Kind: "https", Target: "https://probe.example", RTTMS: 20, OK: true}, nil)
	}
	old := c.selectionSnapshot()
	for range 100 {
		c.remoteEvidence(true, contract.HealthSample{Kind: "https", Target: "https://probe.example", RTTMS: 180, OK: true}, nil)
	}
	current := c.selectionSnapshot()
	if old.TCPHealth.Samples[0].RTTMS != 20 || old.TCPHealth.LatencySamples[63].RTTMS != 20 || current.TCPHealth.Samples[0].RTTMS != 180 {
		t.Fatal("new evidence mutated an existing selection snapshot")
	}
	public := c.snapshot()
	public.TCPHealth.Samples[0].RTTMS = 999
	public.TCPHealth.LatencySamples[0].RTTMS = 999
	if c.selectionSnapshot().TCPHealth.Samples[0].RTTMS != 180 || c.selectionSnapshot().TCPHealth.LatencySamples[0].RTTMS != 180 {
		t.Fatal("mutable public status changed selection evidence")
	}
	var sink selectorObservations
	if count := testing.AllocsPerRun(100, func() { sink = c.selectionSnapshot() }); count != 0 {
		t.Fatal("unchanged selection evidence allocated", count)
	}
	if sink.TCPHealth.Sequence != current.TCPHealth.Sequence {
		t.Fatal("unchanged snapshot lost sequence")
	}
}

func TestSelectionObservationsInvalidateRestoredAndReconfiguredHistories(t *testing.T) {
	c := new(nodeCounters)
	c.remoteEvidence(true, contract.HealthSample{Kind: "https", RTTMS: 20, OK: true}, nil)
	old := c.selectionSnapshot()
	// Both records deliberately have the same sequence, so restore cannot be
	// distinguished by sequence alone. It is an ownership boundary.
	restored := nodeTotals{TCPHealth: contract.ChannelHealth{State: "healthy", Sequence: 1, Samples: []contract.HealthSample{{Sequence: 1, At: time.Now().UnixMilli(), Kind: "https", RTTMS: 180, OK: true}}}}
	c.restore(restored)
	if current := c.selectionSnapshot(); current.TCPHealth.Samples[0].RTTMS != 180 || old.TCPHealth.Samples[0].RTTMS != 20 {
		t.Fatal("restore reused an obsolete history")
	}
	o := &nodeObserver{nodes: map[string]*nodeCounters{"a": c}}
	o.invalidateHealth("a")
	if current := c.selectionSnapshot(); len(current.TCPHealth.Samples) != 0 || current.TCPHealth.State != "unknown" {
		t.Fatal("transport generation retained health")
	}
	c.remoteEvidence(false, contract.HealthSample{Kind: "reply", OK: true}, nil)
	if current := c.selectionSnapshot(); len(current.TCPHealth.Samples) != 0 || len(current.UDPHealth.Samples) != 1 {
		t.Fatal("independent channels lost generation reset")
	}
	c.mu.Lock()
	c.throughput = contract.ThroughputMeasurement{At: 1, Target: "https://download.example", DownloadMbps: 10}
	c.mu.Unlock()
	if current := c.selectionSnapshot(); current.Throughput.DownloadMbps != 10 {
		t.Fatal("capacity update was hidden by unchanged health")
	}
}

func TestSelectionObservationsExpireWithoutNewWritesOrMutatingPreviousReaders(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		c := new(nodeCounters)
		c.remoteEvidence(true, contract.HealthSample{Kind: "https", RTTMS: 20, OK: true}, nil)
		old := c.selectionSnapshot().TCPHealth
		time.Sleep(3 * time.Minute)
		current := c.selectionSnapshot().TCPHealth
		if old.State != "healthy" || current.State != "unknown" || len(current.Samples) != 1 || current.Sequence != old.Sequence {
			t.Fatal("cached selection failed to expire without a new observation")
		}
	})
}

func TestSelectionObservationsConcurrentReadersAndEvidence(t *testing.T) {
	c := new(nodeCounters)
	var wg sync.WaitGroup
	errs := make(chan error, 8)
	for range 8 {
		wg.Go(func() {
			for range 1000 {
				h := c.selectionSnapshot().TCPHealth
				for _, sample := range h.Samples {
					if sample.RTTMS != 20 || sample.Sequence > h.Sequence {
						errs <- fmt.Errorf("inconsistent immutable history")
						return
					}
				}
			}
		})
	}
	for range 1000 {
		c.remoteEvidence(true, contract.HealthSample{Kind: "https", RTTMS: 20, OK: true}, nil)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
}
