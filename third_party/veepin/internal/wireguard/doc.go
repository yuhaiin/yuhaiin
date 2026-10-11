// Package wireguard is the WireGuard engine: the client session and the
// multi-peer server that the public wireguard package configures, and the
// AmneziaWG wire transform both of them can carry.
//
// It sits on the three protocol packages beneath it -- wire (the message
// codec), noise (the Noise_IKpsk2 handshake and the cookie exchange) and
// transport (the data-path AEAD) -- and on dataplane's pump for everything that
// is not WireGuard-specific. It parses no text: ClientConfig and ServerConfig
// arrive decoded and validated, which is the public package's job.
//
// Both roles run one goroutine that reads the socket and one that reads the
// TUN, the pump's model; the server's read loop is also the only goroutine
// that handles handshakes, which is what lets peer state and the load meter go
// without locks of their own.
package wireguard
