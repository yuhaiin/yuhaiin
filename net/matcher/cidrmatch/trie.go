package cidrmatch

import "log"

// TrieTree trie tree
type TrieTree struct {
	root *node
}

type node struct {
	isLast bool
	mark   string
	left   *node
	right  *node
}

// Insert insert node to tree
func (trie *TrieTree) Insert(str, mark string) {
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
			nodeTemp.mark = mark
		}
	}
}

// Search search from trie tree
func (trie *TrieTree) Search(str string) (isMatch bool, mark string) {
	nodeTemp := trie.root
	for i := 0; i < len(str); i++ {
		if str[i] == 49 {
			nodeTemp = nodeTemp.right
		}
		if str[i] == 48 {
			nodeTemp = nodeTemp.left
		}
		if nodeTemp == nil {
			return false, ""
		}
		if nodeTemp.isLast == true {
			return true, nodeTemp.mark
		}
	}
	return false, ""
}

// GetRoot get root node
func (trie *TrieTree) GetRoot() *node {
	return trie.root
}

// PrintTree print this tree
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

// NewTrieTree create a new trie tree
func NewTrieTree() *TrieTree {
	return &TrieTree{
		root: &node{},
	}
}
