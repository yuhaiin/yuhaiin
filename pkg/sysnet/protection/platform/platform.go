// Package platform selects this platform's Network Protection backend:
// macOS PF through the protection service, Linux nftables and Windows WFP
// from the Yuhaiin process; elsewhere protection is unsupported.
package platform
