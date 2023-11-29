package netapi

type PreferIPv6 struct{}

type SourceKey struct{}

func (SourceKey) String() string { return "Source" }

type InboundKey struct{}

func (InboundKey) String() string { return "Inbound" }

type DestinationKey struct{}

func (DestinationKey) String() string { return "Destination" }

type FakeIPKey struct{}

func (FakeIPKey) String() string { return "FakeIP" }

type CurrentKey struct{}
