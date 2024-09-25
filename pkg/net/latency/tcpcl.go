package latency

import (
	"context"
	"strconv"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/net/dialer"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
)

// TCPDelay get once delay by tcp
func TCPConnectLatency(address, portstr string) (time.Duration, error) {
	port, err := strconv.ParseUint(portstr, 10, 16)
	if err != nil {
		return 0, err
	}

	timeNow := time.Now()
	ctx, cancel := context.WithTimeout(context.TODO(), 3*time.Second)
	defer cancel()
	conn, err := dialer.DialHappyEyeballsv2(ctx, netapi.ParseAddressPort("tcp", address, uint16(port)))
	if err != nil {
		return 0, err
	}
	defer func() {
		_ = conn.Close()
	}()
	return time.Since(timeNow), nil
}
