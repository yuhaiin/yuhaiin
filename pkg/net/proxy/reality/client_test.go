package reality

import (
	"context"
	"io"
	"testing"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/fixed"
	"github.com/Asutorufa/yuhaiin/pkg/protos/config"
	"github.com/Asutorufa/yuhaiin/pkg/protos/node"
	"github.com/Asutorufa/yuhaiin/pkg/utils/assert"
	"google.golang.org/protobuf/proto"
)

func TestClient(t *testing.T) {
	lis, err := fixed.NewServer(config.Tcpudp_builder{
		Host:    proto.String("127.0.0.1:2096"),
		Control: config.TcpUdpControl_disable_udp.Enum(),
	}.Build())
	assert.NoError(t, err)
	defer lis.Close()

	rlis, err := NewServer(config.Reality_builder{
		Dest: proto.String("223.5.5.5:443"),
		ShortId: []string{
			"123456",
		},
		ServerName: []string{"www.xxxxxx.com"},
		PrivateKey: proto.String("SHzPN9uMCvhoAz6ZlUFvCyy3rnFmUNv7b26nXTaTtFE"),
		PublicKey:  proto.String("irzN8QFNFHUl4q_KXMTrk4yMLXKEPlM322C2QedY_yU"),
		Debug:      proto.Bool(true),
		// Mldsa65Seed: proto.String("fFCePvoqxpzzl2FOVjh4N7XxMQ7M8Opo4Dmn02TrxY8"),
	}.Build(), lis)
	assert.NoError(t, err)
	defer rlis.Close()

	go func() {
		for {
			conn, err := rlis.Accept()
			if err != nil {
				break
			}

			go func() {
				defer conn.Close()

				for {
					buf := make([]byte, 1024)
					n, err := conn.Read(buf)
					if err == io.EOF {
						break
					}
					assert.NoError(t, err)

					_, _ = conn.Write(buf[:n])
				}
			}()
		}
	}()

	time.Sleep(time.Second)

	pp, err := fixed.NewClient(node.Fixed_builder{
		Host: proto.String("127.0.0.1"),
		Port: proto.Int32(2096),
	}.Build(), nil)
	assert.NoError(t, err)

	pp, err = NewClient(node.Reality_builder{
		ServerName: proto.String("www.xxxxxx.com"),
		ShortId:    proto.String("123456"),
		PublicKey:  proto.String("irzN8QFNFHUl4q_KXMTrk4yMLXKEPlM322C2QedY_yU"),
		Debug:      proto.Bool(true),
		// Mldsa65Verify: proto.String("-bMV_ZqC9IrxJ2Kx7YJ8XQBkn1VvA5cnJ6Ms9t4MyBc5Iaroznlu9eGQ1UtrpkMch2p8ZA2BQ8Plk88P-imodOsJgciqdgBHDhg6dfB-CFpAGadR7jPiJ6YqMITJujhfpCUNwqLOsJtZXtjK_YgcX93GzY4yh_jvoD4CROxgZG822la3ELXJ81z5f7oASKB4_GoiFaZSvEmJVdACrMuGjC4dqkCV2fWjmx12vqnG6b7m-vd-7WIwWO_yA0jNsQl59i3dwv16yZkWD85YyLpDL4SMNkKIzhioCLrNjWVZIf4y3MET0WRU_6HK04xztlGTx0mPpMvWSXptnijFKcSA7eFy2Pv2EqnaL0-0961JTmdcgijQTsWSGAFs6RLbZXIlrae_shK_coXlVy62cR9wfntHPYbsUkHwGZcAA-XnB7Rm7p6sh-OFz4mopxU9I5Kx5YFhrlpjiYTG6RHK8kyExPt0v-DD8BbnE5PMnnwylroaHUrzWzkKNGdJci4HXKruGHZXZUuYR9nvqjYiQDZefTTCMAjnMo3_4kmlAjo0rzQXXgv8TIMXuAzlRoGSqV8o9bgJ79KlQmJPeYCdnY-EMVNNyK1AoLB_yqTa3BhIWDp_daSO5jOAsLSXgVT8KbobBSyB6_K50vrdgQ8FUPm6msbNxH0j6nu4xjEEqMXbnC33gwIRaTvvJ1TIziLmWe-4tKM1iyEhQ37Jt0qW14Uzwwl9SZZDqZ5ISyfEiqwYl7JN0YIXqhjTraJfmF_rVeFUHch70xb5jTYCuEq9sb4aW-ewDcfkEmdaKZVxy4efR0AxEUjrmY2ndrcW-sxJu-h07HZnB90ETkOWsALC9yB6HnPG0w690DO8XYaHEevPLIl-L9rhe7zC1ngxKukbWXf0LNc17sWpjz3nBhTDvJ3k_oKg4zwH340cv31EXi5aMrlGMqi9wLWxIySTUFI46tRGO1sNHG0qi8md43tZu_BW8eber2IIPXbXbb5fRixg8hBR00mgf0EPJnpDIzt91TEa3Z0wwRfT7w5MpVpDqxvyfk_N-TdqE3irsQtGZPIDQ4ViUZXBfeymUL5KaKZw22UXH535wcFTWawVR02lXjBFI2KhVKiVZcO1Eq0gbjk8jSfF-jHjUWm-LUHMIkwkfh7owHtJGck0q3t0ns7uSjL55WT7WKWOxOejCp6gTosbXFLgIuzAIFZ6EFP_rAXo1DqEY0SkB8QtoS0ydtbUuZC9kjQ-9QMCWrcrVBm81a9EBDE5A0Tk5KSs0PdVg4AULE0vn5Sxn_iq2QebAQ7QX2iD7PN_9QkaoaosuSfXI_dQDKiwXmu-tjNnaCIVZYARk7Tsi-zE9-cZ_3-Ih3EZ1Wqr-i0ooGwtIv3B28IHLp52uS7ym0_aLlR5RX8P2Qvw7Z7avpfQ9HZ6Tel7L9yaNCk1TfbNpv1UUA1wh7nYNd2WlqCfkvgX3NMJ235g8ls6jn7xobCxIqLTji1by0D1MYI87UFYaXRP2RX72hDY8s8Ck3elVnK_JIkNT7mQhed2gYXaohigC7PSm9Q7Oo_cVyY76oOWtPYgu8LOHMVi19S_kdT2SXMe_6Lo1iXFl5t66GUGTwnrvafjTAmcdaDpawYcsUiVTFK0AJWu0GrpXwBh9Wu6_k_J30b1ZSkQH1NavijNMjplCOLTlyXdvjc5VpW9Njr3G1-lWt9dSDpnuqce6cg72afoyAhI0aKnyclCd6Ylp6ZuDGHNxMuLvHlIxx8sU6GVWiDI3pGUz1XVO63UlOM_I8P0AmLFvXlMlC9V4c55E2F_gcdvDcty1qPWS6v5CF_FF_VzH-OjOFBbLWJbIV9QsrbifZR991eszXn4wF6NL31hBhznIpbHV1LAcpIRgQLTcBg8ycD0DWmo_EV9HWB0XnRFLqTdUkOKaIEk2IyYZcN24tsKy6xmROGR6amZu-PuOm9aDZc3JciaHR9a8kIF99-EAZj9YldLZb7CgIfloJloHk7YhfwomvPppN_Ank-XRR2EDvXyYCDut_gHjGc69II9IsMXgqNTe_aX8GDtsits4X5XG5YVPYbJZrzODLakAkUthejxnJO6uFx6XPSKrGsvkocxAKctxqG7p7j0h9CeI8NuUD8MtosdVacwXEqzz-254eZS39UqOfK7RaFxuSBwBmKEkgx6sYaPdKahdWJjF3BTeBIcwdpjKAYcbxbqGWFcJ0l-LtqxHxaVF4Xyhyo-EymQwykd2myVR3YMhYXz7XXfU4pMXWnl1-sEgo9toaPCW-xkBvo-46jaTVjoycfRMwyDm7BRCjG-On7FUc4hoUi-UF53IFuHK_sS6bNq8imEqkux9U4pZsquX4LEzpr-6rPDHiNb_Wj_lsXDlaQem2xw7dX49Fy56B97rUybCA1jv2n6OJxPRlTEfC2EB04XiRFY6bSuVmQ9ZDSsG2CP-GSSJF9WDkyDaZvRMNpGXLgHRSTkZy_ayCV30a6gJHU7VJ6q3qHzp2CSaoW9raQfMulnFLMe1ZCrqUI175RpLx4g40co3sFWFY7BqP56WnnFZaVaS1VTs2PRZQxBEVYG6iSX9THSyyRH15OI8fEmwJ1N1dlXjDJfpYmn8Dw"),
	}.Build(), pp)
	assert.NoError(t, err)

	conn, err := pp.Conn(context.Background(), netapi.EmptyAddr)
	assert.NoError(t, err)
	defer conn.Close()

	_, _ = conn.Write([]byte("aaa"))

	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	assert.NoError(t, err)

	t.Log(string(buf[:n]))
}
