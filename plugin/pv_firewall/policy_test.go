package pv_firewall

import (
	"testing"
)

const (
	POLICY_FILE = "policys/policy.json"
	POLICY_URI  = "http://127.0.0.1:8000/policys/policy.json"
)

func TestLoadPolicy(t *testing.T) {
	p := newFirewallPolicy()

	err := p.LoadPolicy(POLICY_FILE)
	if err != nil {
		t.Errorf("Load policy from file failed: %s", err)
	}

	err = p.LoadPolicy("/test/unexisted_file")
	if err == nil {
		t.Errorf("Should return error, load policy from an unexisted file")
	}
}

func TestPolicyMatch(t *testing.T) {
	p := newFirewallPolicy()
	p.LoadPolicy(POLICY_FILE)

	//testcase designed for the policy file: policys/policy.json
	testcases := []struct {
		domain string
		client string
		found  bool
		action Action
	}{
		{"benign.net", "127.0.0.1", true, ALLOW},
		{"xbenign.net", "127.0.0.1", false, PASS},
		{"benign.net", "10.1.1.1", true, BLOCK},
		{"benign.net", "10.1.2.1", true, ALLOW},
		{"malicious.net", "127.0.0.1", true, ALLOW},
		{"malicious.net", "127.0.0.2", true, BLOCK},
		{"porn.com", "127.0.0.1", true, REDIRECT},
		{"video.porn.com", "127.0.0.1", true, BLOCK},
		{"x.video.porn.com", "127.0.0.1", true, BLOCK},
		{"edu.video.porn.com", "127.0.0.1", true, ALLOW},
	}
	for i, tc := range testcases {
		action, found := p.Match(tc.client, tc.domain)
		if found != tc.found {
			t.Errorf("Test [%d]<%s:%s>: found expected %t, got %t", i, tc.domain, tc.client, tc.found, found)
		}
		if action != tc.action {
			t.Errorf("Test [%d]<%s:%s>: action expected %s, got %s", i, tc.domain, tc.client, actionToString(tc.action), actionToString(action))
		}
	}

}
