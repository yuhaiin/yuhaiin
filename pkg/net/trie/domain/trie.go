package domain

var (
	_        uint8 = 0
	last     uint8 = 1
	wildcard uint8 = 2
)

type trie[T any] struct {
	Value  T                   `json:"value"`
	Symbol uint8               `json:"symbol"`
	Child  map[string]*trie[T] `json:"child"`
}

func (d *trie[T]) child(s string, insert bool) (*trie[T], bool) {
	if insert {
		if d.Child == nil {
			d.Child = make(map[string]*trie[T])
		}

		if d.Child[s] == nil {
			d.Child[s] = &trie[T]{}
		}
	} else {
		if d.Child == nil {
			return nil, false
		}
	}

	r, ok := d.Child[s]
	return r, ok
}

func search[T any](root *trie[T], domain *fqdnReader) (t T, ok bool) {

	first, asterisk := true, false

	for domain.hasNext() {
		r, cok := root.child(domain.str(), false)
		switch cok {
		case false:
			if !first {
				return
			}

			if asterisk {
				domain.next()
				continue
			}

			root, cok = root.child("*", false)
			if !cok {
				return
			}

			asterisk = true

		case true:
			switch r.Symbol {
			case wildcard:
				t, ok = r.Value, true
			case last:
				if domain.last() {
					return r.Value, true
				}
			}

			root = r
			domain.next()
			first = false
		}
	}

	return
}

func insert[T any](node *trie[T], z *fqdnReader, mark T) {
	for z.hasNext() {
		if z.last() && z.str() == "*" {
			node.Symbol, node.Value = wildcard, mark
			break
		}

		node, _ = node.child(z.str(), true)

		if z.last() {
			node.Symbol, node.Value = last, mark
		}

		z.next()
	}
}

type deleteElement[T any] struct {
	str  string
	node *trie[T]
}

func remove[T any](node *trie[T], domain *fqdnReader) {
	// fmt.Println("remove", domain.domain)

	nodes := []*deleteElement[T]{
		{
			str:  "root",
			node: node,
		},
	}

	for domain.hasNext() {
		z, ok := node.child(domain.str(), false)
		if !ok {
			if domain.str() == "*" && node.Symbol == wildcard {
				break
			}
			return
		}

		node = z
		nodes = append(nodes, &deleteElement[T]{domain.str(), node})
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
