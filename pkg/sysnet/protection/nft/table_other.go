//go:build !linux || android

package nft

// Supported reports whether this platform has the nftables backend.
const Supported = false
