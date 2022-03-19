package pv_firewall

import (
	"github.com/coredns/caddy"
	"github.com/coredns/coredns/plugin"
)

// init registers this plugin.
func init() { plugin.Register("pv_firewall", setup) }

func parseConfig(c *caddy.Controller) (FirewallPolicy, error) {
	c.Next() // directive name

}

func setup(c *caddy.Controller) error {
	policy, err := parseConfig(c)

	if err != nil {
		return plugin.Error("pv_firewall", err)
	}
}
