package latency

import (
	"testing"
)

func TestTCPDelay(t *testing.T) {
	t.Log(TCPConnectLatency("www.baidu.com", "443"))
	t.Log(TCPConnectLatency("www.google.com", "443"))
}
