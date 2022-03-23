package pv_firewall

import (
	"context"

	"github.com/coredns/coredns/plugin"
	"github.com/miekg/dns"
)

type PVFirewall struct {
	Policy FirewallPolicy
	Next   plugin.Handler
}

func (f PVFirewall) ServeDNS(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) (int, error) {

	log.Info("Received response")

	// Call next plugin (if any).
	return plugin.NextOrFailure(f.Name(), f.Next, ctx, w, r)
}

func (f PVFirewall) Name() string { return "PV Firewall" }
