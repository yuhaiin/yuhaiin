package hysteria2

import (
    "github.com/apernet/quic-go"
    "github.com/Asutorufa/yuhaiin/pkg/net/proxy/hysteria2/internal/congestion"
    "github.com/Asutorufa/yuhaiin/pkg/net/proxy/hysteria2/internal/congestion/bbr"
)

// UseBBRForMASQUE shares the Hysteria 2 BBR controller with MASQUE QUIC sessions.
func UseBBRForMASQUE(conn *quic.Conn) {
    congestion.UseBBR(conn, bbr.ProfileStandard)
}
