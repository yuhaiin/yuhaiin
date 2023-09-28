package domain

var (
	_        uint8 = 0
	last     uint8 = 1
	wildcard uint8 = 2
)

type domainNode[T any] struct {
	Mark   T                         `json:"mark"`
	Symbol uint8                     `json:"symbol"`
	Child  map[string]*domainNode[T] `json:"child"`
}

func (d *domainNode[T]) wChild(s string) *domainNode[T] {
	if d.Child == nil {
		d.Child = make(map[string]*domainNode[T])
	}

	if d.Child[s] == nil {
		d.Child[s] = &domainNode[T]{}
	}

	return d.Child[s]
}

func (d *domainNode[T]) rChild(s string) *domainNode[T] {
	if d.Child == nil || d.Child[s] == nil {
		return &domainNode[T]{}
	}

	return d.Child[s]
}

func (d *domainNode[T]) childExist(s string) bool { return d.Child != nil && d.Child[s] != nil }

func search[T any](node *domainNode[T], domain *domainReader) (resp T, ok bool) {
	first, asterisk := true, false

	for domain.hasNext() && node != nil {
		if !node.childExist(domain.str()) {
			if !first {
				return
			}

			if !asterisk {
				node, asterisk = node.rChild("*"), true
			} else {
				domain.next()
			}

			continue
		}

		node = node.rChild(domain.str())

		if node.Symbol != 0 {
			if node.Symbol == wildcard {
				resp, ok = node.Mark, true
			}

			if node.Symbol == last && domain.last() {
				return node.Mark, true
			}
		}

		first, _ = false, domain.next()
	}

	return
}

func insert[T any](node *domainNode[T], z *domainReader, mark T) {
	for z.hasNext() {
		if z.last() && z.str() == "*" {
			node.Symbol, node.Mark = wildcard, mark
			break
		}

		node = node.wChild(z.str())

		if z.last() {
			node.Symbol, node.Mark = last, mark
		}

		z.next()
	}
}

type deleteElement[T any] struct {
	str  string
	node *domainNode[T]
}

func remove[T any](node *domainNode[T], domain *domainReader) {
	// fmt.Println("remove", domain.domain)

	var nodes []*deleteElement[T]

	nodes = append(nodes, &deleteElement[T]{
		str:  "root",
		node: node,
	})

	for domain.hasNext() && node != nil {
		if !node.childExist(domain.str()) {
			if domain.str() == "*" && node.Symbol == wildcard {
				break
			}
			return
		}

		node = node.rChild(domain.str())
		nodes = append(nodes, &deleteElement[T]{
			str:  domain.str(),
			node: node,
		})
		domain.next()
	}

	if node.Symbol == 0 {
		return
	}

	for i := len(nodes) - 1; i >= 0; i-- {
		if len(nodes[i].node.Child) != 0 {
			if i == len(nodes)-1 {
				nodes[i].node.Symbol = 0
			}
			break
		}

		if len(nodes[i].node.Child) == 0 {
			if i-1 > 0 {
				delete(nodes[i-1].node.Child, nodes[i].str)
			}
		}
	}

	// for _, v := range nodes {
	// 	fmt.Println(v.str, len(v.node.Child), maps.Keys(v.node.Child))
	// }
}
