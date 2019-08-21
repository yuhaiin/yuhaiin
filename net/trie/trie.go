package trie

import "log"

type TrieTree struct {
	root *node
}

type node struct {
	isLast bool
	left   *node
	right  *node
}

func (trie *TrieTree) Insert(str string) {
	nodeTemp := trie.root
	for i := 0; i < len(str); i++ {
		// 1 byte is 49
		if str[i] == 49 {
			if nodeTemp.right == nil {
				nodeTemp.right = new(node)
			}
			nodeTemp = nodeTemp.right
		}
		// 0 byte is 48
		if str[i] == 48 {
			if nodeTemp.left == nil {
				nodeTemp.left = new(node)
			}
			nodeTemp = nodeTemp.left
		}
		if i == len(str)-1 {
			nodeTemp.isLast = true
		}
	}
}

func (trie *TrieTree) Search(str string) bool {
	nodeTemp := trie.root
	for i := 0; i < len(str); i++ {
		if str[i] == 49 {
			nodeTemp = nodeTemp.right
		}
		if str[i] == 48 {
			nodeTemp = nodeTemp.left
		}
		if nodeTemp == nil {
			return false
		}
		if nodeTemp.isLast == true {
			return true
		}
	}
	return false
}

func (trie *TrieTree) GetRoot() *node {
	return trie.root
}

func (trie *TrieTree) PrintTree(node *node) {
	if node.left != nil {
		trie.PrintTree(node.left)
		log.Println("0")
	}
	if node.right != nil {
		trie.PrintTree(node.right)
		log.Println("1")
	}
}

func NewTrieTree() *TrieTree {
	return &TrieTree{
		root: &node{},
	}
}

func _() {
	trieTree := NewTrieTree()
	trieTree.Insert("101")
	trieTree.Insert("001")
	trieTree.Insert("101111")
	log.Println(trieTree.Search("1011"), trieTree.Search("0001"))
	// rootTest.left = &node{
	// 	isLast: true,
	// }
	// rootTest.right = &node{
	// 	isLast: false,
	// }
	trieTree.PrintTree(trieTree.root)
	log.Println(trieTree.GetRoot(), trieTree.GetRoot().right.left.right.isLast, trieTree.GetRoot().left)
}
