package pv_firewall

import (
	"fmt"

	"github.com/coredns/caddy"
	"github.com/coredns/coredns/plugin"
)

// init registers this plugin.
func init() { plugin.Register("pv_firewall", setup) }

func parseConfig(c *caddy.Controller) (FirewallPolicy, error) {
	c.Next() // directive name
	p := FirewallPolicy{}
	uri := ""

	if !c.Args(&uri) {
		return p, c.ArgErr()
	}

	if err := parseFirewallPolicy(uri, &p); err != nil {
		return p, err
	}

	return p, nil

}

func setup(c *caddy.Controller) error {
	policy, err := parseConfig(c)
	fmt.Println(policy)

	if err != nil {
		return plugin.Error("pv_firewall", err)
	}

	return nil
}
