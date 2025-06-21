package networksetup

import "testing"

func TestNetworksetup(t *testing.T) {
	t.Run("ListAllNetworkServices", func(t *testing.T) {
		data, err := ListAllNetworkServices()
		if err != nil {
			t.Fatal(err)
		}

		for _, v := range data {
			t.Logf("--%s--", v)
		}
	})

	t.Run("ListAllDNSServers", func(t *testing.T) {
		data, err := ListAllDNSServers("Wi-Fi")
		if err != nil {
			t.Fatal(err)
		}

		for _, v := range data {
			t.Logf("--%s--", v)
		}
	})
}
