package netlink

import (
	"errors"
	"testing"
)

func TestSharedRouteRulesOwnershipAndRetry(t *testing.T) {
	for _, owned := range []bool{true, false} {
		var rules sharedRouteRules
		creates, deletes := 0, 0
		create := func() (bool, error) { creates++; return owned, nil }
		fail := true
		remove := func() error {
			deletes++
			if fail {
				return errors.New("delete rule failed")
			}
			return nil
		}
		for range 2 {
			if err := rules.acquire(4, create); err != nil {
				t.Fatal(err)
			}
		}
		if creates != 1 {
			t.Fatal("shared rule was created more than once")
		}
		if err := rules.release(4, remove); err != nil {
			t.Fatal(err)
		}
		if deletes != 0 {
			t.Fatal("removed rule while another TUN needed it")
		}
		if owned {
			if err := rules.release(4, remove); err == nil {
				t.Fatal("missing delete error")
			}
			if rules.leases[4] == nil {
				t.Fatal("lost failed rule cleanup record")
			}
			fail = false
			if err := rules.release(4, remove); err != nil {
				t.Fatal(err)
			}
			if deletes != 2 {
				t.Fatal("failed rule cleanup not retried")
			}
		} else {
			if err := rules.release(4, remove); err != nil {
				t.Fatal(err)
			}
			if deletes != 0 {
				t.Fatal("deleted a borrowed rule")
			}
		}
		if len(rules.leases) != 0 {
			t.Fatal("lease not released")
		}
	}
}

func TestSharedRouteRulesFailedAcquisition(t *testing.T) {
	var rules sharedRouteRules
	if err := rules.acquire(6, func() (bool, error) { return false, errors.New("create rule failed") }); err == nil {
		t.Fatal("missing create error")
	}
	if len(rules.leases) != 0 {
		t.Fatal("registered a rule that was never installed")
	}
}
