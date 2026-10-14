package resolver

import (
	"codeberg.org/miekg/dns"
	"testing"
)

func TestUDPResponseIsVisibleWhenQueryWakes(t *testing.T) {
	response := &udpresp{}
	message := &dns.Msg{Response: true}
	notified := false
	response.cancel = func() {
		notified = true
		if response.msg.Load() != message {
			t.Error("query woke before the response was available")
		}
	}
	response.setMsg(message)
	if !notified {
		t.Fatal("query was not notified")
	}
}
