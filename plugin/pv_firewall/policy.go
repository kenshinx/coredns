package pv_firewall

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
)

type Action int
type TargetType int

const (
	ALLOW Action = iota
	BLOCK
	REDIRECT
	INVALIDACTION
)

const (
	T_IP TargetType = iota
	T_NET
	T_ALL
	T_UNKOWN
)

type Target struct {
	TValue string
	TType  TargetType
}

func newTarget(target string) Target {
	var ttype TargetType
	if isIP(target) {
		ttype = T_IP
	} else if isNET(target) {
		ttype = T_NET
	} else if target == "all" {
		ttype = T_ALL
	} else {
		ttype = T_UNKOWN
	}
	return Target{target, ttype}
}

type Rule struct {
	IoC     string
	Targets map[Target]Action
}

func (r *Rule) insert(target string, action string) {
	t := newTarget(target)
	r.Targets[t] = r.mapAction(action)
}

func (r *Rule) mapAction(action string) Action {
	var a Action
	switch strings.ToLower(action) {
	case "allow":
		a = ALLOW
	case "block":
		a = BLOCK
	case "redirect":
		a = REDIRECT
	default:
		a = INVALIDACTION
	}
	return a
}

type FirewallPolicy struct {
	Policy *suffixTreeNode
	mu     *sync.RWMutex
}

func newFirewallPolicy() FirewallPolicy {
	return FirewallPolicy{
		Policy: newSuffixTree(),
		mu:     new(sync.RWMutex),
	}
}

func parseFirewallPolicy(uri string, p *FirewallPolicy) error {
	var payload map[string]map[string]string

	if !isURL(uri) {
		return fmt.Errorf("firewall policy must be assigned to a valid url")
	}

	resp, err := http.Get(uri)
	if err != nil {
		return fmt.Errorf("request policy failed:%s", err)
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("read policy failed:%s", err)
	}

	err = json.Unmarshal(body, &payload)
	if err != nil {
		return fmt.Errorf("json decode policy failed:%s", err)
	}

	p.mu.Lock()
	defer p.mu.Unlock()
	for ioc, rules := range payload {
		r := Rule{
			IoC:     ioc,
			Targets: make(map[Target]Action),
		}
		for target, action := range rules {
			r.insert(target, action)
		}
		p.Policy.Sinsert(strings.Split(ioc, "."), r)

	}

	return nil
}

func isURL(s string) bool {
	_, err := url.ParseRequestURI(s)
	return err == nil
}

func isIP(s string) bool {
	return net.ParseIP(s) != nil
}

func isNET(s string) bool {
	_, _, err := net.ParseCIDR(s)
	return err == nil
}
