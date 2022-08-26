package simplehttp

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"

	"github.com/Asutorufa/yuhaiin/pkg/net/utils"
	grpcnode "github.com/Asutorufa/yuhaiin/pkg/protos/grpc/node"
	"github.com/Asutorufa/yuhaiin/pkg/protos/node"
	"google.golang.org/protobuf/types/known/emptypb"
)

type subHandler struct {
	emptyHTTP
	nm grpcnode.NodeManagerServer
}

func (s *subHandler) Post(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	link := r.URL.Query().Get("link")

	if name == "" || link == "" {
		http.Error(w, "name or link is empty", http.StatusInternalServerError)
		return
	}

	_, err := s.nm.SaveLinks(context.TODO(), &node.SaveLinkReq{
		Links: []*node.NodeLink{
			{
				Name: name,
				Url:  link,
			},
		},
	})
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Write(nil)
}

func (s *subHandler) Get(w http.ResponseWriter, r *http.Request) {
	links, err := s.nm.GetLinks(context.TODO(), &emptypb.Empty{})
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	str := utils.GetBuffer()
	defer utils.PutBuffer(str)

	str.Write(toastHTML)
	str.WriteString("<script>")
	str.Write(subJS)
	str.WriteString("</script>")
	ls := make([]string, 0, len(links.Links))
	for v := range links.Links {
		ls = append(ls, v)
	}
	sort.Strings(ls)

	for _, v := range ls {
		l := links.Links[v]
		str.WriteString("<div>")
		str.WriteString(fmt.Sprintf(`<input type="checkbox" name="links" value="%s"/>`, l.GetName()))
		str.WriteString(fmt.Sprintf(`<a href='javascript: linkSelectOrCopy("%s","%s");'>%s</a>`, l.GetName(), l.GetUrl(), l.GetName()))
		str.WriteString("</div>")
	}

	str.WriteString("<br/>")
	str.WriteString(`<a href='javascript:update()'>UPDATE</a>`)
	str.WriteString("&nbsp;&nbsp;&nbsp;&nbsp;")
	str.WriteString(`<a href='javascript:delSubs()'>DELETE</a>`)
	str.WriteString("<br/>")

	str.WriteString("<hr/>")
	str.WriteString("Add a New Link<br/><br/>")
	str.WriteString(`Name:`)
	str.WriteString("&nbsp;&nbsp;")
	str.WriteString(`<input type="text" id="name" value="">`)
	str.WriteString("<br/>")
	str.WriteString(`Link:`)
	str.WriteString("&nbsp;&nbsp;")
	str.WriteString(`<input type="text" id="link" value="">`)
	str.WriteString("<br/>")
	str.WriteString(`<a href="javascript: add();">ADD</a>`)
	w.Write([]byte(createHTML(str.String())))
}

func (s *subHandler) Delete(w http.ResponseWriter, r *http.Request) {
	data := r.URL.Query().Get("links")
	if data == "" {
		w.Write(nil)
		return
	}

	var names []string

	if err := json.Unmarshal([]byte(data), &names); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	_, err := s.nm.DeleteLinks(context.TODO(), &node.LinkReq{Names: names})
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Write(nil)
}

func (s *subHandler) Patch(w http.ResponseWriter, r *http.Request) {
	data := r.URL.Query().Get("links")
	if data == "" {
		w.Write(nil)
		return
	}

	var names []string
	if err := json.Unmarshal([]byte(data), &names); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	_, err := s.nm.UpdateLinks(context.TODO(), &node.LinkReq{Names: names})
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Write(nil)
}
