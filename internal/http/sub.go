package simplehttp

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"sort"

	grpcnode "github.com/Asutorufa/yuhaiin/pkg/protos/node/grpc"
	"github.com/Asutorufa/yuhaiin/pkg/protos/node/subscribe"
	"google.golang.org/protobuf/types/known/emptypb"
)

type subHandler struct {
	emptyHTTP
	nm grpcnode.SubscribeServer
}

func (s *subHandler) Post(w http.ResponseWriter, r *http.Request) error {
	name := r.URL.Query().Get("name")
	link := r.URL.Query().Get("link")

	if name == "" || link == "" {
		return errors.New("name or link is empty")
	}

	_, err := s.nm.Save(context.TODO(), &grpcnode.SaveLinkReq{
		Links: []*subscribe.Link{
			{
				Name: name,
				Url:  link,
			},
		},
	})
	if err != nil {
		return err
	}

	w.Write(nil)
	return nil
}

func (s *subHandler) Get(w http.ResponseWriter, r *http.Request) error {
	links, err := s.nm.Get(context.TODO(), &emptypb.Empty{})
	if err != nil {
		return err
	}

	ls := make([]string, 0, len(links.Links))
	for v := range links.Links {
		ls = append(ls, v)
	}
	sort.Strings(ls)

	return TPS.BodyExecute(w, map[string]any{"LS": ls, "Links": links.Links}, "sub.html")
}

func (s *subHandler) Delete(w http.ResponseWriter, r *http.Request) error {
	data := r.URL.Query().Get("links")
	if data == "" {
		w.Write(nil)
		return nil
	}

	var names []string

	if err := json.Unmarshal([]byte(data), &names); err != nil {
		return err
	}

	_, err := s.nm.Remove(context.TODO(), &grpcnode.LinkReq{Names: names})
	if err != nil {
		return err
	}

	w.Write(nil)
	return nil
}

func (s *subHandler) Patch(w http.ResponseWriter, r *http.Request) error {
	data := r.URL.Query().Get("links")
	if data == "" {
		w.Write(nil)
		return nil
	}

	var names []string
	if err := json.Unmarshal([]byte(data), &names); err != nil {
		return err
	}

	_, err := s.nm.Update(context.TODO(), &grpcnode.LinkReq{Names: names})
	if err != nil {
		return err
	}

	w.Write(nil)
	return nil
}
