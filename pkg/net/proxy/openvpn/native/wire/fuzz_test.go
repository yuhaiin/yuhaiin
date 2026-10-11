// Adapted from xen0bit/veepin (MIT). See ../THIRD_PARTY_LICENSE.
package wire

import "testing"

// Fuzz targets for the OpenVPN packet codec.
//
// The opcode byte and session IDs are read before the TLS control channel has
// established anything, so a server parses this from any host that can reach
// its UDP port.

func FuzzParseControl(f *testing.F) {
	f.Add([]byte{})
	f.Add(make([]byte, 14))

	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = ParseControl(data)
	})
}
