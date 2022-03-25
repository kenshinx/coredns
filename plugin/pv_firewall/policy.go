package pv_firewall

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
)

type Action int
type TargetType int

const (
	T_IP TargetType = iota
	T_NET
	T_ALL
	T_UNKOWN
)

const (
	ALLOW Action = iota
	BLOCK
	REDIRECT
	PASS
	INVALIDACTION
)

var ActionStringMap = map[Action]string{
	ALLOW:         "Allow",
	BLOCK:         "Block",
	REDIRECT:      "Redirect",
	PASS:          "Pass",
	INVALIDACTION: "Invalid Action",
}

func actionToString(action Action) string {
	a, _ := ActionStringMap[action]
	return a
}

func actionToInt(action string) Action {
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
		log.Warningf("Rules contain invalid action: %s", action)
	}
	return a
}

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
		log.Warningf("Rules contain invalid target: %s", target)
	}
	return Target{target, ttype}
}

type Rule struct {
	IoC     string
	Targets map[Target]Action
}

func (r *Rule) insert(target string, action string) {
	t := newTarget(target)
	r.Targets[t] = actionToInt(action)
}

func (r *Rule) match(clientIP string) (action Action, found bool) {
	cidrs := make(map[*net.IPNet]Action)
	matchALL := false
	defaultAction := PASS

	//match IP firstly, net secondly,  and then match "all", if all missed, return PASS
	for target, action := range r.Targets {
		switch target.TType {
		case T_IP:
			if target.TValue == clientIP {
				return action, true //match IP
			}
		case T_NET:
			if _, cidr, err := net.ParseCIDR(target.TValue); err == nil {
				cidrs[cidr] = action
			}
		case T_ALL:
			matchALL = true
			defaultAction = action // match ALL
		case T_UNKOWN:
		}
	}

	for cidr, action := range cidrs {
		if cidr.Contains(net.ParseIP(clientIP)) {
			return action, true
		}
	}

	if matchALL {
		return defaultAction, true
	}

	return PASS, false
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

func (p *FirewallPolicy) Match(clientIP string, qname string) (action Action, found bool) {
	p.mu.RLock()
	v, found := p.Policy.Search(strings.Split(qname, "."))
	p.mu.RUnlock()
	if !found {
		return PASS, false
	}
	rule := v.(Rule)
	return rule.match(clientIP)

}

func (p *FirewallPolicy) LoadPolicy(path string) error {
	var err error
	var body []byte
	var payload map[string]map[string]string

	if isFile(path) {
		if body, err = p.loadFromFile(path); err != nil {
			return fmt.Errorf("load policy from file:%s failed, error:%s", path, err)
		}
	} else if isURL(path) {
		if body, err = p.loadFromURL(path); err != nil {
			return fmt.Errorf("load policy from uri:%s failed, error:%s", path, err)
		}
	} else {
		return fmt.Errorf("policy must be assigned to a url or local file, current: %s", path)
	}

	err = json.Unmarshal(body, &payload)
	if err != nil {
		return fmt.Errorf("json decode policy failed:%s", err)
	}

	for ioc, rules := range payload {
		r := Rule{
			IoC:     ioc,
			Targets: make(map[Target]Action),
		}
		for target, action := range rules {
			r.insert(target, action)
		}
		p.mu.Lock()
		p.Policy.Sinsert(strings.Split(ioc, "."), r)
		p.mu.Unlock()

	}
	log.Infof("Fetch policy from %s, got [%d] rules", path, len(payload))

	return nil

}

func (p *FirewallPolicy) loadFromURL(uri string) (body []byte, err error) {

	resp, err := http.Get(uri)
	if err != nil {
		return nil, fmt.Errorf("request policy failed:%s", err)
	}
	defer resp.Body.Close()

	body, err = ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read policy failed:%s", err)
	}

	return body, nil
}

func (p *FirewallPolicy) loadFromFile(file string) (body []byte, err error) {
	return os.ReadFile(file)
}

func isURL(s string) bool {
	_, err := url.Parse(s)
	return err == nil
}

func isFile(s string) bool {
	file, err := os.Open(s)
	defer file.Close()
	return err == nil
}

func isIP(s string) bool {
	return net.ParseIP(s) != nil
}

func isNET(s string) bool {
	_, _, err := net.ParseCIDR(s)
	return err == nil
}
