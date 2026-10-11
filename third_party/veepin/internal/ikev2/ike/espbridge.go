package ike

import (
	"fmt"

	"github.com/xen0bit/veepin/internal/ikev2/esp"
)

// BuildESPSA converts a negotiated Child SA into a userspace esp.SA, wiring the
// directional keys and the negotiated transform IDs into the ESP data path.
//
// The returned SA uses the Child SA's inbound SPI to open received packets and
// its outbound SPI to protect sent packets, mirroring the key directions
// assigned during negotiation. IntegID is zero for AEAD suites, which
// authenticate with the cipher itself.
func BuildESPSA(child *ChildSA) (*esp.SA, error) {
	if child.Suite.EncrID == 0 {
		return nil, fmt.Errorf("ike: child SA has no negotiated cipher")
	}
	return &esp.SA{
		SPIOut: child.OutboundSPI,
		SPIIn:  child.InboundSPI,
		Out: esp.Transform{
			EncrID:    child.Suite.EncrID,
			EncrKeyLn: child.Suite.EncrKeyLn,
			IntegID:   child.Suite.IntegID,
			EncKey:    child.EncrOut,
			IntegKey:  child.IntegOut,
		},
		In: esp.Transform{
			EncrID:    child.Suite.EncrID,
			EncrKeyLn: child.Suite.EncrKeyLn,
			IntegID:   child.Suite.IntegID,
			EncKey:    child.EncrIn,
			IntegKey:  child.IntegIn,
		},
	}, nil
}
