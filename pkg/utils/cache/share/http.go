package share

import (
	"bytes"
	"context"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"fmt"
	"io"
	"iter"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/log"
	"github.com/Asutorufa/yuhaiin/pkg/utils/cache"
	"github.com/Asutorufa/yuhaiin/pkg/utils/syncmap"
)

type Server struct {
	db      cache.Cache
	dbCache syncmap.SyncMap[string, cache.Cache]
	lis     *net.UnixListener
}

func NewServer(unixPath string, db cache.Cache) (*Server, error) {
	log.Info("start kv server", "path", unixPath)
	lis, err := net.ListenUnix("unix", &net.UnixAddr{Name: unixPath, Net: "unix"})
	if err != nil {
		return nil, err
	}
	s := &Server{
		db:  db,
		lis: lis,
	}
	go s.Start()
	return s, nil
}

func (s *Server) Start() {
	mux := http.NewServeMux()
	mux.HandleFunc("/get", Serve(s.Get))
	mux.HandleFunc("/set", Serve(s.Set))
	mux.HandleFunc("/delete", Serve(s.Delete))
	mux.HandleFunc("/range", s.Range)
	mux.HandleFunc("/ping", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte{'{', '}'})
	})
	srv := http.Server{
		Handler: mux,
	}
	err := srv.Serve(s.lis)
	if err != nil {
		log.Error("failed to serve", "err", err)
	}
}

func (s *Server) Close() error {
	return s.lis.Close()
}

func Serve[Req any, Res any](f func(Req) (Res, error)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req Req
		err := json.UnmarshalRead(r.Body, &req)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		res, err := f(req)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		data, err := json.Marshal(res)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		_, err = w.Write(data)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
	}
}

type GetRequest struct {
	Buckets []string `json:"buckets,omitempty"`
	Key     []byte   `json:"key,omitempty"`
}

type GetResponse struct {
	Value []byte `json:"value,omitempty"`
}

func (s *Server) getCache(buckets ...string) cache.Cache {
	key := strings.Join(buckets, "-")
	cache, _, _ := s.dbCache.LoadOrCreate(key, func() (cache.Cache, error) {
		return s.db.NewCache(buckets...), nil
	})

	return cache
}

func (s *Server) Get(req GetRequest) (GetResponse, error) {
	cache := s.getCache(req.Buckets...)

	value, err := cache.Get(req.Key)
	if err != nil {
		return GetResponse{}, err
	}

	return GetResponse{Value: value}, nil
}

type Object struct {
	Key   []byte `json:"key,omitempty"`
	Value []byte `json:"value,omitempty"`
}

type SetRequest struct {
	Buckets []string `json:"buckets,omitempty"`
	Objects []Object `json:"objects,omitempty"`
}

func (s *SetRequest) Range() iter.Seq2[[]byte, []byte] {
	return func(yield func([]byte, []byte) bool) {
		for _, o := range s.Objects {
			if !yield(o.Key, o.Value) {
				break
			}
		}
	}
}

func (s *Server) Set(req SetRequest) (struct{}, error) {
	return struct{}{}, s.getCache(req.Buckets...).Put(req.Range())
}

type DeleteRequest struct {
	Buckets []string `json:"buckets,omitempty"`
	Keys    [][]byte `json:"keys,omitempty"`
}

func (s *Server) Delete(req DeleteRequest) (struct{}, error) {
	return struct{}{}, s.getCache(req.Buckets...).Delete(req.Keys...)
}

type RangeRequest struct {
	Buckets []string `json:"buckets,omitempty"`
}

func (s *Server) Range(w http.ResponseWriter, r *http.Request) {
	var req RangeRequest
	if err := json.UnmarshalRead(r.Body, &req); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	cc := s.getCache(req.Buckets...)

	enc := jsontext.NewEncoder(w)

	err := cc.Range(func(k []byte, v []byte) bool {
		err := json.MarshalEncode(enc, Object{Key: k, Value: v})
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return false
		}
		return true
	})
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
}

type Client struct {
	client  *http.Client
	buckets []string
}

func NewClient(unixPath string, buckets ...string) *Client {
	return &Client{
		buckets: buckets,
		client: &http.Client{
			Timeout: time.Second * 2,
			Transport: &http.Transport{
				DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
					return net.DialUnix("unix", nil, &net.UnixAddr{
						Net:  "unix",
						Name: unixPath,
					})
				},
			},
		},
	}
}

func (c *Client) sendRaw(path string, req []byte) (*http.Response, error) {
	r, err := http.NewRequest("POST", "http://127.0.0.1"+path, bytes.NewReader(req))
	if err != nil {
		return nil, err
	}
	r.Header.Set("Content-Type", "application/json")
	resp, err := c.client.Do(r)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != http.StatusOK {
		defer resp.Body.Close()
		data, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("status code %d: %s", resp.StatusCode, data)
	}

	return resp, nil
}

func (c *Client) SendRequest(path string, req any, res any) error {
	body, err := json.Marshal(req)
	if err != nil {
		return err
	}
	resp, err := c.sendRaw(path, body)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	return json.UnmarshalRead(resp.Body, res)
}

func (c *Client) Get(k []byte) (v []byte, err error) {
	var res GetResponse
	err = c.SendRequest("/get", GetRequest{Buckets: c.buckets, Key: k}, &res)
	return res.Value, err
}

func (c *Client) Put(r iter.Seq2[[]byte, []byte]) error {
	var objects []Object
	for k, v := range r {
		objects = append(objects, Object{
			Key:   k,
			Value: v,
		})
	}
	var res struct{}
	return c.SendRequest("/set", SetRequest{Buckets: c.buckets, Objects: objects}, &res)
}
func (c *Client) Delete(k ...[]byte) error {
	var res struct{}
	return c.SendRequest("/delete", DeleteRequest{Buckets: c.buckets, Keys: k}, &res)
}
func (c *Client) Range(f func(key []byte, value []byte) bool) error {
	data, err := json.Marshal(RangeRequest{
		Buckets: c.buckets,
	})
	if err != nil {
		return err
	}

	r, err := c.sendRaw("/range", data)
	if err != nil {
		return err
	}
	defer r.Body.Close()

	dec := jsontext.NewDecoder(r.Body)
	for {
		var o Object
		err := json.UnmarshalDecode(dec, &o)
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
		if !f(o.Key, o.Value) {
			break
		}
	}
	return nil
}

func (c *Client) Ping() error {
	var res struct{}
	return c.SendRequest("/ping", struct{}{}, &res)
}

func (c *Client) NewCache(str ...string) cache.Cache {
	return &Client{
		client:  c.client,
		buckets: append(c.buckets, str...),
	}
}
