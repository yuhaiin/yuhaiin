package domain

var (
	_        uint8 = 0
	last     uint8 = 1
	wildcard uint8 = 2
)

type domainNode[T any] struct {
	Symbol uint8                     `json:"symbol"`
	Mark   T                         `json:"mark"`
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
