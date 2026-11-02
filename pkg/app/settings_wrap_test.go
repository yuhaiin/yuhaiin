package app

import (
	"strings"
	"testing"

	contractsettings "github.com/Asutorufa/yuhaiin/pkg/contract/settings"
)

func TestValidateWrapSettingsTimezone(t *testing.T) {
	for _, tc := range []struct {
		name     string
		timezone string
		valid    bool
	}{
		{name: "inherit", timezone: "", valid: true},
		{name: "utc", timezone: "UTC", valid: true},
		{name: "unknown zone", timezone: "Mars/Olympus", valid: false},
		{name: "newline", timezone: "UTC\nTZ=UTC", valid: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := contractsettings.WrapSettings{Timezone: tc.timezone}
			err := validateWrapSettings(cfg)
			if (err == nil) != tc.valid {
				t.Fatalf("timezone %q: validity=%v err=%v", tc.timezone, tc.valid, err)
			}
			if err != nil && !strings.Contains(err.Error(), "timezone") {
				t.Fatalf("unexpected validation error: %v", err)
			}
		})
	}
}
