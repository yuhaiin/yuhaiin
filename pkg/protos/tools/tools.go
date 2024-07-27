package tools

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/Asutorufa/yuhaiin/pkg/config"
	"github.com/Asutorufa/yuhaiin/pkg/log"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	pc "github.com/Asutorufa/yuhaiin/pkg/protos/config"
	"github.com/Asutorufa/yuhaiin/pkg/route"
	"github.com/Asutorufa/yuhaiin/pkg/utils/relay"
	"github.com/Asutorufa/yuhaiin/pkg/utils/system"
	"google.golang.org/protobuf/types/known/emptypb"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

type Tools struct {
	UnimplementedToolsServer
	setting  config.Setting
	dialer   netapi.Proxy
	callback func(*pc.Setting)
}

func NewTools(dialer netapi.Proxy, setting config.Setting, callback func(st *pc.Setting)) *Tools {
	return &Tools{
		setting:  setting,
		dialer:   dialer,
		callback: callback,
	}
}

func (t *Tools) SaveRemoteBypassFile(ctx context.Context, url *wrapperspb.StringValue) (*emptypb.Empty, error) {
	hc := &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				add, err := netapi.ParseAddress(network, addr)
				if err != nil {
					return nil, err
				}
				return t.dialer.Conn(ctx, add)
			},
		},
	}

	st, err := t.setting.Load(context.TODO(), &emptypb.Empty{})
	if err != nil {
		return nil, err
	}

	parentDir, _ := filepath.Abs(filepath.Dir(st.Bypass.BypassFile))
	inurlDir := path.Join(parentDir, "rule_cache")

	_ = os.RemoveAll(inurlDir)

	if err := os.MkdirAll(parentDir, os.ModePerm); err != nil {
		return nil, err
	}

	if err := os.MkdirAll(inurlDir, os.ModePerm); err != nil {
		return nil, err
	}

	err = get(hc, parentDir, url.Value, func(r io.Reader) error {

		scanner := bufio.NewScanner(r)

		f, err := os.OpenFile(st.Bypass.BypassFile, os.O_CREATE|os.O_RDWR|os.O_TRUNC, os.ModePerm)
		if err != nil {
			return err
		}

		for scanner.Scan() {
			text := scanner.Text()

			before := route.TrimComment(text)

			scheme, _, _ := system.GetScheme(before)
			switch scheme {
			case "file", "http", "https":
				url, _, ok := route.SplitHostArgs(before)
				if !ok {
					url = before
				}
				err := get(hc, parentDir, url, func(r io.Reader) error {
					if ok {
						data, err := io.ReadAll(r)
						if err != nil {
							return err
						}

						hash := getFileHash(data)

						filen := filepath.Join(inurlDir, hash)

						_, _ = f.WriteString("# " + url + "\n" + "file:\"" + filen + "\"" + strings.Replace(text, url, "", 1) + "\n")
						return os.WriteFile(filen, data, 0644)
					} else {
						_, err := relay.Copy(f, r)
						return err
					}
				})
				if err != nil {
					log.Warn("get file failed", "err", err)
				}

				continue
			}

			_, _ = f.WriteString(text + "\n")
		}

		_ = f.Close()

		if t.callback != nil {
			t.callback(st)
		}

		return nil
	})

	return &emptypb.Empty{}, err
}

func getFileHash(data []byte) string {
	h := sha256.New()
	h.Write(data)
	return hex.EncodeToString(h.Sum(nil))
}

func get(hc *http.Client, rulepath string, url string, ff func(io.Reader) error) error {
	scheme, etc, _ := system.GetScheme(url)
	switch scheme {
	case "file":
		file := strings.TrimPrefix(etc, "//")
		if !filepath.IsAbs(file) {
			file = filepath.Join(rulepath, file)
		}

		f, err := os.Open(file)
		if err != nil {
			return err
		}
		defer f.Close()
		return ff(f)
	default:
		resp, err := hc.Get(url)
		if err != nil {
			return err
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			data, _ := io.ReadAll(resp.Body)
			return fmt.Errorf("http status: %d, %s", resp.StatusCode, string(data))
		}

		return ff(resp.Body)
	}
}

func (t *Tools) GetInterface(context.Context, *emptypb.Empty) (*Interfaces, error) {
	is := &Interfaces{}
	iis, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	for _, i := range iis {
		if i.Flags&net.FlagLoopback != 0 {
			continue
		}
		iif := &Interface{
			Name: i.Name,
		}

		addresses, err := i.Addrs()
		if err == nil {
			for _, a := range addresses {
				iif.Addresses = append(iif.Addresses, a.String())
			}
		}
		is.Interfaces = append(is.Interfaces, iif)
	}

	return is, nil
}
