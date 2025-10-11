package ac

import "github.com/Asutorufa/yuhaiin/pkg/utils/list"

type ac struct {
	root *acNode
}

type acNode struct {
	fail *acNode
	node map[rune]*acNode
	mark string
}

func (a *ac) search(str string, f func(string) bool) {
	p := a.root

	for _, c := range str {
		for p != a.root {
			if _, ok := p.node[c]; ok {
				break
			}
			p = p.fail
		}

		z, ok := p.node[c]
		if !ok {
			continue
		}

		p = z

		if p.mark != "" {
			if !f(p.mark) {
				return
			}
		}

		if p.fail.mark != "" {
			if !f(p.fail.mark) {
				return
			}
		}
	}
}

func (a *ac) Search(str string) []string {
	resp := []string{}

	a.search(str, func(s string) bool {
		resp = append(resp, s)
		return true
	})

	return resp
}

func (a *ac) Exist(str string) bool {
	resp := false

	a.search(str, func(s string) bool {
		resp = true
		return false
	})

	return resp
}

func (a *ac) Insert(str string) {
	p := a.root
	for _, c := range str {
		if p.node[c] == nil {
			p.node[c] = &acNode{node: make(map[rune]*acNode)}
		}
		p = p.node[c]
	}
	p.mark = str
}

func (a *ac) BuildFail() {
	type queueElem struct {
		p *acNode
		n *acNode
		b rune
	}

	queue := list.New[*queueElem]()
	queue.PushBack(&queueElem{p: a.root, n: a.root})

	for queue.Len() != 0 {
		zz := queue.Front()
		queue.Remove(zz)

		z := zz.Value()
		z.n.fail = a.findFail(z.p, z.b)

		for k, v := range z.n.node {
			queue.PushBack(&queueElem{
				p: z.n,
				n: v,
				b: k,
			})
		}
	}
}

func (a *ac) findFail(parent *acNode, b rune) *acNode {
	if parent == a.root {
		return parent
	}
	if i, ok := parent.fail.node[b]; ok {
		return i
	}
	return a.findFail(parent.fail, b)
}

func NewAC() *ac {
	r := &acNode{node: make(map[rune]*acNode)}
	r.fail = r

	return &ac{root: r}
}
