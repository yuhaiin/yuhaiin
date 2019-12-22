package delay

import (
	"testing"
)

func TestTCPDelay(t *testing.T) {
	t.Log(TCPDelay("www.baidu.com", "443"))
	t.Log(TCPDelay("www.google.com", "443"))
}
