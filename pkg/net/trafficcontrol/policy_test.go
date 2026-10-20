package trafficcontrol

import (
	"encoding/json"
	"testing"
)

func TestPolicyJSONAndDirection(t *testing.T) {
	src := Config{Enabled: true, Profiles: map[string]Profile{"bulk": {Download: Rate{BytesPerSecond: 80000, BurstBytes: 16000}}}, RouteProfiles: map[string]string{"route-1": "bulk"}}
	raw, err := json.Marshal(src)
	if err != nil {
		t.Fatal(err)
	}
	var out Config
	if err = json.Unmarshal(raw, &out); err != nil {
		t.Fatal(err)
	}
	if out.RouteProfiles["route-1"] != "bulk" || out.Profiles["bulk"].Download.BurstBytes != 16000 {
		t.Fatalf("%s -> %+v", raw, out)
	}
}
