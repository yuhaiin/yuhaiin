package main

import (
	"encoding/json"
	"testing"

	yuhaiin "github.com/Asutorufa/yuhaiin/cmd/android"
)

func TestMain(m *testing.T) {
	a := &yuhaiin.Opts{
		DNS: &yuhaiin.DNSSetting{
			Local:     &yuhaiin.DNS{},
			Remote:    &yuhaiin.DNS{},
			Bootstrap: &yuhaiin.DNS{},
		},

		TUN: &yuhaiin.TUN{},
	}

	d, _ := json.MarshalIndent(a, "", "  ")
	m.Log(string(d))
}

func TestShr(t *testing.T) {
	b := 2543
	t.Log(b >> 8)
}
