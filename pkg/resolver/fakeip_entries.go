package resolver

import (
	"context"
	"errors"

	contractresolver "github.com/Asutorufa/yuhaiin/pkg/contract/resolver"
)

var _ contractresolver.FakeIPEntries = (*Fakedns)(nil)

func (f *Fakedns) ListFakeIPEntries(ctx context.Context, page, size int, query string) ([]contractresolver.FakeIPEntry, int, error) {
	f.fakeMu.RLock()
	defer f.fakeMu.RUnlock()
	if f.fake == nil {
		return nil, 0, errors.New("fake DNS is closed")
	}
	return f.fake.ListEntries(ctx, page, size, query)
}

func (f *Fakedns) DeleteFakeIPEntry(ctx context.Context, entry contractresolver.FakeIPEntry) (contractresolver.FakeIPDeleteResponse, error) {
	f.fakeMu.RLock()
	defer f.fakeMu.RUnlock()
	if f.fake == nil {
		return contractresolver.FakeIPDeleteResponse{}, errors.New("fake DNS is closed")
	}
	return f.fake.DeleteEntry(ctx, entry)
}
