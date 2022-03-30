package mapper

type ac struct {
	root *acNode
}

type acNode struct {
	fail *acNode
	mark string
	node map[rune]*acNode
}

func (a *ac) search(str string) []string {
	p := a.root
	resp := []string{}

	for _, c := range str {
		_, ok := p.node[c]
		for !ok && p != a.root {
			p = p.fail
			_, ok = p.node[c]
		}

		if _, ok = p.node[c]; ok {
			p = p.node[c]
			if p.mark != "" {
				resp = append(resp, p.mark)
			}
			if p.fail.mark != "" {
				resp = append(resp, p.fail.mark)
			}
		}
	}
	return resp
}

func (a *ac) searchLongest(str string) string {
	p := a.root
	resp := ""

	for _, c := range str {
		_, ok := p.node[c]
		for !ok && p != a.root {
			p = p.fail
			_, ok = p.node[c]
		}

		if _, ok = p.node[c]; ok {

			p = p.node[c]
			if p.mark != "" {
				resp = p.mark
			}
			// if p.fail.mark != "" {
			// resp = p.fail.mark
			// }
		}
	}

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
	que := newQueue()
	que.push(&queueElem{p: a.root, n: a.root})

	for que.size() != 0 {
		z := que.pop()
		z.n.fail = a.findFail(z.p, z.b)

		for k, v := range z.n.node {
			que.push(&queueElem{
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

type queueElem struct {
	p *acNode
	n *acNode
	b rune
}
type queue struct {
	qu []*queueElem
}

func newQueue() *queue {
	return &queue{
		qu: []*queueElem{},
	}
}

func (q *queue) pop() *queueElem {
	if len(q.qu) == 0 {
		return &queueElem{}
	}
	x := q.qu[0]
	q.qu = q.qu[1:]
	return x
}

func (q *queue) push(x *queueElem) {
	q.qu = append(q.qu, x)
}

func (q *queue) size() int {
	return len(q.qu)
}
func NewAC() *ac {
	r := &acNode{node: make(map[rune]*acNode)}
	r.fail = r

	return &ac{root: r}
}
