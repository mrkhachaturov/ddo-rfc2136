package dnsop

import (
	"fmt"
	"net"
	"strconv"
	"time"

	"github.com/bodgit/tsig/gss"
	"github.com/miekg/dns"
)

type RealClient struct {
	GSS           *gss.Client
	Realm         string
	Principal     string
	AxfrTimeout   time.Duration
	UpdateTimeout time.Duration
}

func (c *RealClient) AXFR(host string, port int, zone string) RecordsResult {
	addr := net.JoinHostPort(host, strconv.Itoa(port))
	keyName, _, err := c.GSS.NegotiateContext(addr)
	if err != nil {
		return RecordsResult{OK: false, Phase: "gss-negotiate", Message: err.Error(), Retryable: true}
	}
	defer func() { _ = c.GSS.DeleteContext(keyName) }()

	m := new(dns.Msg)
	m.SetAxfr(dns.Fqdn(zone))
	m.SetTsig(keyName, "gss-tsig.", 300, time.Now().Unix())

	t := &dns.Transfer{
		TsigProvider: c.GSS,
		DialTimeout:  c.AxfrTimeout,
		ReadTimeout:  c.AxfrTimeout,
	}
	ch, err := t.In(m, addr)
	if err != nil {
		return RecordsResult{OK: false, Phase: "dns-send", Message: err.Error(), Retryable: true}
	}
	return ParseAXFRStream(ch)
}

func (c *RealClient) Update(host string, port int, zone string, prereqs []Prereq, changes []Change) ApplyResult {
	addr := net.JoinHostPort(host, strconv.Itoa(port))
	keyName, _, err := c.GSS.NegotiateContext(addr)
	if err != nil {
		return ApplyResult{OK: false, Phase: "gss-negotiate", Message: err.Error(), Retryable: true}
	}
	defer func() { _ = c.GSS.DeleteContext(keyName) }()

	m, err := BuildUpdateMsg(zone, prereqs, changes)
	if err != nil {
		return ApplyResult{OK: false, Phase: "dns-send", Message: err.Error(), Retryable: false}
	}
	m.SetTsig(keyName, "gss-tsig.", 300, time.Now().Unix())

	cli := &dns.Client{
		Net:          "tcp",
		TsigProvider: c.GSS,
		DialTimeout:  c.UpdateTimeout,
		ReadTimeout:  c.UpdateTimeout,
		WriteTimeout: c.UpdateTimeout,
	}
	resp, _, err := cli.Exchange(m, addr)
	if err != nil {
		return ApplyResult{OK: false, Phase: "dns-send", Message: err.Error(), Retryable: true}
	}
	if resp == nil {
		return ApplyResult{OK: false, Phase: "dns-receive", Message: "nil response", Retryable: true}
	}
	return ClassifyRcode(resp.Rcode)
}

// Convenience for main.go wiring.
func NewRealClient(realm, principal string, axfr, upd time.Duration) (*RealClient, error) {
	g, err := gss.NewClient(new(dns.Client))
	if err != nil {
		return nil, fmt.Errorf("gss new client: %w", err)
	}
	return &RealClient{
		GSS:           g,
		Realm:         realm,
		Principal:     principal,
		AxfrTimeout:   axfr,
		UpdateTimeout: upd,
	}, nil
}
