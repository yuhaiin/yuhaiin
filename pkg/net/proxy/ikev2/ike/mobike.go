package ike

import "github.com/Asutorufa/yuhaiin/pkg/net/proxy/ikev2/payload"

func findMobikeSupported(inners []payload.RawPayload) bool {
	for _, p := range inners {
		if p.Type != payload.TypeNotify {
			continue
		}
		if n, err := payload.ParseNotify(p.Body); err == nil && n.Type == payload.MobikeSupported {
			return true
		}
	}
	return false
}

func addMobikeSupported(b *payload.Builder) {
	b.Add(payload.TypeNotify, false, payload.MarshalNotify(payload.NotifyPayload{
		Protocol: payload.ProtoNone, Type: payload.MobikeSupported,
	}))
}

func findNotify(inners []payload.RawPayload, t payload.NotifyType) *payload.NotifyPayload {
	for _, p := range inners {
		if p.Type != payload.TypeNotify {
			continue
		}
		if n, err := payload.ParseNotify(p.Body); err == nil && n.Type == t {
			return &n
		}
	}
	return nil
}
