package resolver

import "context"

// FakeIPEntry identifies one mapping in an active address pool.
type FakeIPEntry struct {
	Domain string `json:"domain"`
	IP     string `json:"ip"`
}

type FakeIPDeleteResponse struct {
	Removed int `json:"removed"`
}

type FakeIPEntries interface {
	ListFakeIPEntries(context.Context, int, int, string) ([]FakeIPEntry, int, error)
	DeleteFakeIPEntry(context.Context, FakeIPEntry) (FakeIPDeleteResponse, error)
}
