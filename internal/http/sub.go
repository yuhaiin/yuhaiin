package simplehttp

import (
	"encoding/json"
	"errors"
	"net/http"
	"sort"

	grpcnode "github.com/Asutorufa/yuhaiin/pkg/protos/node/grpc"
	"github.com/Asutorufa/yuhaiin/pkg/protos/node/subscribe"
	"golang.org/x/exp/maps"
	"google.golang.org/protobuf/types/known/emptypb"
)

type subHandler struct {
	nm grpcnode.SubscribeServer
}

func (s *subHandler) Post(w http.ResponseWriter, r *http.Request) error {
	name := r.URL.Query().Get("name")
	link := r.URL.Query().Get("link")

	if name == "" || link == "" {
		return errors.New("name or link is empty")
	}

	_, err := s.nm.Save(r.Context(), &grpcnode.SaveLinkReq{
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

func (s *subHandler) GetLinkList(w http.ResponseWriter, r *http.Request) error {
	links, err := s.nm.Get(r.Context(), &emptypb.Empty{})
	if err != nil {
		return err
	}

	linksValue := maps.Values(links.Links)

	sort.Slice(linksValue, func(i, j int) bool { return linksValue[i].Name < linksValue[j].Name })

	data, err := json.Marshal(linksValue)
	if err != nil {
		return err
	}

	w.Write(data)
	return nil
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

	_, err := s.nm.Remove(r.Context(), &grpcnode.LinkReq{Names: names})
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

	_, err := s.nm.Update(r.Context(), &grpcnode.LinkReq{Names: names})
	if err != nil {
		return err
	}

	w.Write(nil)
	return nil
}
