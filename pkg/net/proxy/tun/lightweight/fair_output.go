package lightweight

import "github.com/Asutorufa/yuhaiin/pkg/net/trafficcontrol"

func (s *Stack) initOutput(mode trafficcontrol.SchedulerMode, packets int, bytes int64) {
	s.output = trafficcontrol.NewOutputQueue(trafficcontrol.OutputOptions[*ownedBuffer]{
		Limits: trafficcontrol.FairConfig{MaxPackets: packets, MaxBytes: bytes}, Mode: mode,
		Size:     func(p *ownedBuffer) int { return len(outputBytes(p)) },
		Classify: func(p *ownedBuffer) trafficcontrol.Classification { return trafficcontrol.Classify(outputBytes(p)) },
		Release:  func(p *ownedBuffer) { p.release(); s.drops.Add(1) },
	})
}
func (s *Stack) dequeueOutput(wait bool) (*ownedBuffer, bool) {
	p, ok := s.output.Dequeue(s.done, wait)
	if ok {
		s.wakeOutput()
	}
	return p, ok
}
func outputBytes(p *ownedBuffer) []byte {
	if p == nil || p.offset < 0 || p.offset >= len(p.data) {
		return nil
	}
	return p.data[p.offset:]
}
