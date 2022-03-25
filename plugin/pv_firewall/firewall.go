package pv_firewall

import (
	"context"
	"net"
	"strings"

	"github.com/coredns/coredns/plugin"
	"github.com/coredns/coredns/request"
	"github.com/miekg/dns"
)

const (
	REDIRECT_IPV4 = "127.0.0.1"
	REDIRECT_IPV6 = "::1"
	REDIRECT_TTL  = 600
)

type PVFirewall struct {
	Policy FirewallPolicy
	Next   plugin.Handler
}

func (f *PVFirewall) ServeDNS(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) (int, error) {
	state := request.Request{W: w, Req: r}

	action, found := f.Policy.Match(state.IP(), strings.TrimSuffix(state.QName(), "."))
	if !found {
		return plugin.NextOrFailure(f.Name(), f.Next, ctx, w, r)
	}

	switch action {
	case ALLOW:
		return plugin.NextOrFailure(f.Name(), f.Next, ctx, w, r)
	case BLOCK:
		return dns.RcodeRefused, nil
	case REDIRECT:
		m := new(dns.Msg)
		m.SetReply(r)
		m.Authoritative = true
		m.Answer = redirect(state.QName(), state.QType())
		m.Rcode = dns.RcodeRefused
		w.WriteMsg(m)
		return dns.RcodeRefused, nil
	}

	return plugin.NextOrFailure(f.Name(), f.Next, ctx, w, r)
}

func (f *PVFirewall) Name() string { return "PV Firewall" }

func redirect(qname string, qtype uint16) []dns.RR {
	answers := make([]dns.RR, 1)
	switch qtype {
	case dns.TypeAAAA:
		r := new(dns.AAAA)
		r.Hdr = dns.RR_Header{Name: qname, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: REDIRECT_TTL}
		r.AAAA = net.ParseIP(REDIRECT_IPV6)
		answers[0] = r
	default:
		r := new(dns.A)
		r.Hdr = dns.RR_Header{Name: qname, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: REDIRECT_TTL}
		r.A = net.ParseIP(REDIRECT_IPV4)
		answers[0] = r
	}
	return answers
}
