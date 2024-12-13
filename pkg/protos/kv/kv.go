package kv

import (
	context "context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/log"
	"github.com/Asutorufa/yuhaiin/pkg/utils/cache"
	"github.com/Asutorufa/yuhaiin/pkg/utils/cache/bbolt"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	emptypb "google.golang.org/protobuf/types/known/emptypb"
)

var _ KvstoreServer = (*KV)(nil)

type KV struct {
	db *bbolt.Cache
	UnimplementedKvstoreServer
}

func NewKV(db *bbolt.Cache) *KV {
	return &KV{db: db}
}

func (k *KV) Get(ctx context.Context, e *Element) (*Element, error) {
	c := k.db

	for _, v := range e.Buckets {
		c = c.NewCache(v).(*bbolt.Cache)
	}

	var err error
	e.Value, err = c.Get(e.Key)
	return e, err
}

func (k *KV) Set(ctx context.Context, e *Element) (*emptypb.Empty, error) {
	c := k.db
	for _, v := range e.Buckets {
		c = c.NewCache(v).(*bbolt.Cache)
	}

	err := c.Put(e.Key, e.Value)
	return &emptypb.Empty{}, err
}

func (k *KV) Delete(ctx context.Context, req *Keys) (*emptypb.Empty, error) {
	c := k.db
	for _, v := range req.Buckets {
		c = c.NewCache(v).(*bbolt.Cache)
	}
	err := c.Delete(req.Keys...)
	return &emptypb.Empty{}, err
}

func (k *KV) Range(req *Element, s grpc.ServerStreamingServer[Element]) error {
	c := k.db
	for _, v := range req.Buckets {
		c = c.NewCache(v).(*bbolt.Cache)
	}
	return c.Range(func(k []byte, v []byte) bool {
		err := s.Send(&Element{
			Buckets: req.Buckets,
			Key:     k,
			Value:   v,
		})
		if err != nil {
			log.Error("failed to send", "err", err)
			return false
		}
		return true
	})
}

func (k *KV) Ping(context.Context, *emptypb.Empty) (*emptypb.Empty, error) {
	return &emptypb.Empty{}, nil
}

type closer struct {
	path string
	s    *grpc.Server
	lis  *net.UnixListener
}

func (c *closer) Close() error {
	_ = os.Remove(c.path)
	c.s.Stop()
	return c.lis.Close()
}

func Start(unixPath string, db *bbolt.Cache) (io.Closer, error) {
	slog.Info("start kv server", "path", unixPath)
	lis, err := net.ListenUnix("unix", &net.UnixAddr{Name: unixPath, Net: "unix"})
	if err != nil {
		return nil, err
	}

	gs := grpc.NewServer()

	gs.RegisterService(&Kvstore_ServiceDesc, &KV{db: db})
	go func() {
		if err := gs.Serve(lis); err != nil {
			log.Error("failed to serve", "err", err)
		}
	}()

	return &closer{unixPath, gs, lis}, nil
}

type KVStoreCli struct {
	buckets []string
	conn    *grpc.ClientConn
	KvstoreClient
}

func (c *KVStoreCli) Close() error {
	return c.conn.Close()
}

func (c *KVStoreCli) Get(k []byte) ([]byte, error) {
	resp, err := c.KvstoreClient.Get(context.Background(), &Element{
		Buckets: c.buckets,
		Key:     k,
	})
	if err != nil {
		log.Error("failed to get", "err", err)
		return nil, err
	}

	return resp.Value, nil
}
func (c *KVStoreCli) Put(k []byte, v []byte) error {
	_, err := c.KvstoreClient.Set(context.Background(), &Element{
		Buckets: c.buckets,
		Key:     k,
		Value:   v,
	})
	if err != nil {
		log.Error("failed to set", "err", err)
		return err
	}

	return nil
}

func (c *KVStoreCli) Delete(k ...[]byte) error {
	_, err := c.KvstoreClient.Delete(context.Background(), &Keys{
		Buckets: c.buckets,
		Keys:    k,
	})
	if err != nil {
		log.Error("failed to delete", "err", err)
		return err
	}
	return nil
}

func (c *KVStoreCli) Range(f func(key []byte, value []byte) bool) error {
	s, err := c.KvstoreClient.Range(context.TODO(), &Element{
		Buckets: c.buckets,
	})
	if err != nil {
		log.Error("failed to range", "err", err)
		return err
	}
	defer func() { _ = s.CloseSend() }()

	for {
		resp, err := s.Recv()
		if err == io.EOF {
			break
		}

		if err != nil {
			log.Error("failed to range", "err", err)
			return err
		}

		if !f(resp.Key, resp.Value) {
			break
		}
	}

	return nil
}

func (c *KVStoreCli) NewCache(b string) cache.RecursionCache {
	return &KVStoreCli{
		buckets:       append(c.buckets, b),
		conn:          c.conn,
		KvstoreClient: c.KvstoreClient,
	}
}

func NewClient(unixPath string) (*KVStoreCli, error) {
	conn, err := grpc.NewClient(
		"passthrough://"+unixPath,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithContextDialer(func(ctx context.Context, s string) (net.Conn, error) {
			return net.DialTimeout("unix", unixPath, 2*time.Second)
		}),
	)
	if err != nil {
		return nil, fmt.Errorf("new client failed: %w", err)
	}

	cli := NewKvstoreClient(conn)

	_, err = cli.Ping(context.Background(), &emptypb.Empty{})
	if err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("ping failed: %w", err)
	}
	return &KVStoreCli{conn: conn, KvstoreClient: cli}, nil
}
