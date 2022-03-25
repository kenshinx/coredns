package pv_firewall

import (
	"strings"
	"testing"
)

func TestSuffixTree(t *testing.T) {
	tree := newSuffixTree()

	tree.Sinsert(strings.Split("x.benign.net", "."), "allow")
	tree.Sinsert(strings.Split("malicious.net", "."), "block")
	tree.Sinsert(strings.Split("x.malicious.net", "."), "redirect")
	tree.Sinsert(strings.Split("t.x.malicious.net", "."), "block")
	tree.Sinsert(strings.Split("t.x.malicious.net", "."), "allow")

	testcases := []struct {
		domain string
		found  bool
		action interface{}
	}{
		{"x.benign.net", true, "allow"},
		{"y.benign.net", false, struct{}{}},
		{"z.x.benign.net", true, "allow"},
		{"benign.net", false, struct{}{}},
		{"malicious.net", true, "block"},
		{"emalicious.net", false, struct{}{}},
		{"x.malicious.net", true, "redirect"},
		{"y.malicious.net", true, "block"},
		{"z.x.malicious.net", true, "redirect"},
		{"b.t.x.malicious.net", true, "allow"},
	}

	for i, tc := range testcases {
		action, found := tree.Search(strings.Split(tc.domain, "."))
		if found != tc.found {
			t.Errorf("Test [%d]%s: found expected %t, got %t", i, tc.domain, tc.found, found)
		}
		if action != tc.action {
			t.Errorf("Test [%d]%s: action expected %s, got %s", i, tc.domain, tc.action, action)
		}
	}

}
