package latency

import (
	"testing"
)

func TestTCPDelay(t *testing.T) {
	t.Skip("requires external network access")

	t.Log(TCPConnectLatency("www.baidu.com", "443"))
	t.Log(TCPConnectLatency("www.google.com", "443"))
}
