package pv_firewall

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"sync"
)

type Action int
type IType int
type TType int

const (
	ALLOW Action = iota
	BLOCK
	REDIRECT
)

const (
	I_FQDN IType = iota
	I_IP
	I_SLD
	I_SUB //sub domain
)

const (
	T_IP TType = iota
	T_NET
	T_ALL
)

type IoC struct {
	Value string
	Type  IType
}

type Target struct {
	Value string
	Type  TType
}

type Rules map[Target]Action

type FirewallPolicy struct {
	Rules map[IoC]Rules
	mu    sync.RWMutex
}

func parseFirewallPolicy(uri string, p *FirewallPolicy) error {
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

	err = json.Unmarshal(body, p)
	if err != nil {
		return fmt.Errorf("parse policy failed:%s", err)
	}
	return nil
}

func isURL(uri string) bool {
	_, err := url.ParseRequestURI(uri)
	return err == nil
}
