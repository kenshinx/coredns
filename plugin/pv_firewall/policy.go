package pv_firewall

import (
	"sync"
)

type Action int

const (
	Allow Action = iota
	Block
	Redirect
)

type Rule map[string]Action

type FirewallPolicy struct {
	Rules map[string]Rule
	mu    sync.RWMutex
}
