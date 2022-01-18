package mapper

import "strings"

var mapping = map[byte]int{
	'a': 0, 'A': -18,
	'b': 1, 'B': -17,
	'c': 2, 'C': -16,
	'd': 3, 'D': -15,
	'e': 4, 'E': -14,
	'f': 5, 'F': -13,
	'g': 6, 'G': -12,
	'h': 7, 'H': -11,
	'i': 8, 'I': -10,
	'j': 9, 'J': -9,
	'k': 10, 'K': -8,
	'l': 11, 'L': -7,
	'm': 12, 'M': -6,
	'n': 13, 'N': -5,
	'o': 14, 'O': -4,
	'p': 15, 'P': -3,
	'q': 16, 'Q': -2,
	'r': 17, 'R': -1,
	's': 18, 'S': 0,
	't': 19, 'T': 1,
	'u': 20, 'U': 2,
	'v': 21, 'V': 3,
	'w': 22, 'W': 4,
	'x': 23, 'X': 5,
	'y': 24, 'Y': 6,
	'z': 25, 'Z': 7,
	'-': 26,
	'0': 27,
	'1': 28,
	'2': 29,
	'3': 30,
	'4': 31,
	'5': 32,
	'6': 33,
	'7': 34,
	'8': 35,
	'9': 36,
	'*': 37,
}

func getIndex(str string) int {
	resp := 0
	for i, z := range []byte(str) {
		resp += mapping[z] * (i + 1)
	}

	return resp
}

type domain2Node struct {
	last     bool
	wildcard bool
	mark     interface{}
	child    map[int]*domain2Node
}

func search2(root *domain2Node, domain string) (interface{}, bool) {
	return search2DFS(root, domain, true, false, len(domain))
}

func search2DFS(root *domain2Node, domain string, first, asterisk bool, aft int) (interface{}, bool) {
	if root == nil || aft < 0 {
		return nil, false
	}

	pre := strings.LastIndexByte(domain[:aft], '.') + 1

	i := getIndex(domain[pre:aft])
	if r, ok := root.child[i]; ok {
		if r.wildcard {
			return r.mark, true
		}
		if r.last && pre == 0 {
			return r.mark, true
		}
		return search2DFS(r, domain, false, asterisk, pre-1)
	}

	if !first {
		return nil, false
	}

	if !asterisk {
		return search2DFS(root.child[getIndex("*")], domain, first, true, aft)
	}

	return search2DFS(root, domain, first, asterisk, pre-1)
}

func insert2(root *domain2Node, domain string, mark interface{}) {
	aft := len(domain)
	var pre int
	for aft >= 0 {
		pre = strings.LastIndexByte(domain[:aft], '.') + 1

		if pre == 0 && domain[0] == '*' {
			root.wildcard = true
			root.mark = mark
			root.child = make(map[int]*domain2Node) // clear child,because this node is last
			break
		}

		i := getIndex(domain[pre:aft])
		if root.child[i] == nil {
			root.child[i] = &domain2Node{child: make(map[int]*domain2Node)}
		}

		root = root.child[i]

		if pre == 0 {
			root.last = true
			root.mark = mark
			root.child = make(map[int]*domain2Node) // clear child,because this node is last
		}

		aft = pre - 1
	}
}

type domain2 struct {
	root         *domain2Node // for example.com, example.*
	wildcardRoot *domain2Node // for *.example.com, *.example.*
}

func (d *domain2) Insert(domain string, mark interface{}) {
	if len(domain) == 0 {
		return
	}

	if domain[0] == '*' {
		insert2(d.wildcardRoot, domain, mark)
	} else {
		insert2(d.root, domain, mark)
	}
}

func (d *domain2) Search(domain string) (mark interface{}, ok bool) {
	mark, ok = search2(d.root, domain)
	if ok {
		return
	}
	return search2(d.wildcardRoot, domain)
}

func NewDomain2Mapper() *domain2 {
	return &domain2{
		root:         &domain2Node{child: map[int]*domain2Node{}},
		wildcardRoot: &domain2Node{child: map[int]*domain2Node{}},
	}
}
