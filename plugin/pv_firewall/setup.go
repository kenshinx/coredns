package pv_firewall

import (
	"github.com/coredns/caddy"
	"github.com/coredns/coredns/core/dnsserver"
	"github.com/coredns/coredns/plugin"
	clog "github.com/coredns/coredns/plugin/pkg/log"
)

var log = clog.NewWithPlugin("pv_firewall")

// init registers this plugin.
func init() { plugin.Register("pv_firewall", setup) }

func parseConfig(c *caddy.Controller) (FirewallPolicy, error) {
	c.Next() // directive name
	p := newFirewallPolicy()
	uri := ""

	if !c.Args(&uri) {
		return p, c.ArgErr()
	}

	if err := p.LoadPolicy(uri); err != nil {
		return p, err
	}

	return p, nil

}

func setup(c *caddy.Controller) error {
	policy, err := parseConfig(c)
	if err != nil {
		return plugin.Error("pv_firewall", err)
	}

	firewall := PVFirewall{Policy: policy}

	dnsserver.GetConfig(c).AddPlugin(
		func(next plugin.Handler) plugin.Handler {
			firewall.Next = next
			return firewall
		})

	return nil
}
