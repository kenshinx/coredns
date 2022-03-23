package pv_firewall

const WILDCARD string = "*"

type suffixTreeNode struct {
	key      string
	value    interface{}
	children map[string]*suffixTreeNode
}

func newSuffixTree() *suffixTreeNode {
	return newSuffixTreeNode(".", struct{}{})
}

func newSuffixTreeNode(key string, value interface{}) *suffixTreeNode {
	root := &suffixTreeNode{
		key:      key,
		value:    value,
		children: map[string]*suffixTreeNode{},
	}
	return root
}

func (node *suffixTreeNode) EnsureSubTree(key string) {
	if _, ok := node.children[key]; !ok {
		node.children[key] = newSuffixTreeNode(key, struct{}{})
	}
}

func (node *suffixTreeNode) Insert(key string, value interface{}) {
	if c, ok := node.children[key]; ok {
		c.value = value
	} else {
		node.children[key] = newSuffixTreeNode(key, value)
	}
}

func (node *suffixTreeNode) Sinsert(keys []string, value interface{}) {
	if len(keys) == 0 {
		return
	}

	key := keys[len(keys)-1]
	if len(keys) > 1 {
		node.EnsureSubTree(key)
		node.children[key].Sinsert(keys[:len(keys)-1], value)
		return
	}

	node.Insert(key, value)
}

func (node *suffixTreeNode) match(key string) (*suffixTreeNode, bool) {
	n, ok := node.children[key]
	if ok {
		return n, ok
	}
	n, ok = node.children[WILDCARD]
	return n, ok
}

func (node *suffixTreeNode) matchWildcard() (*suffixTreeNode, bool) {
	n, ok := node.children[WILDCARD]
	return n, ok
}

func (node *suffixTreeNode) Search(keys []string) (interface{}, bool) {
	if len(keys) == 0 {
		return struct{}{}, false
	}

	key := keys[len(keys)-1]
	if n, ok := node.match(key); ok {
		if nextValue, found := n.Search(keys[:len(keys)-1]); found {
			return nextValue, found
		}
		return n.value, (n.value != struct{}{})
	}

	return struct{}{}, false
}
