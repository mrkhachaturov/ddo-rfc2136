package dnsop

import (
	"fmt"
	"log"
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

	// exchange is the function used to send the UPDATE message and receive
	// the response. It defaults to (*dns.Client).Exchange when nil; tests
	// override it to simulate transport / TSIG-verify behaviour without a
	// real DNS server.
	exchange func(client *dns.Client, m *dns.Msg, addr string) (*dns.Msg, time.Duration, error)
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

	exchange := c.exchange
	if exchange == nil {
		exchange = func(client *dns.Client, msg *dns.Msg, a string) (*dns.Msg, time.Duration, error) {
			return client.Exchange(msg, a)
		}
	}

	resp, _, err := exchange(cli, m, addr)
	return classifyExchangeResult(resp, err)
}

// classifyExchangeResult maps a (resp, err) tuple from dns.Client.Exchange into
// an ApplyResult. It is split out from Update so it can be unit-tested without
// a live DNS server or GSS context. The bodgit/tsig response-TSIG verify quirk
// against Active Directory is handled here: when err is non-nil but the
// response is a well-formed NOERROR, AD committed the UPDATE atomically before
// our local TSIG verification ran, so treat it as success and emit a warning.
// Refs: bodgit/tsig#54, hashicorp/terraform-provider-dns#160.
func classifyExchangeResult(resp *dns.Msg, err error) ApplyResult {
	if err != nil {
		if resp != nil && resp.Rcode == dns.RcodeSuccess {
			log.Printf("rfc2136-transport: WARN response TSIG verify quirk (committed, rcode=NOERROR): %v", err)
			return ApplyResult{OK: true, Rcode: "NOERROR"}
		}
		if resp != nil {
			return ClassifyRcode(resp.Rcode)
		}
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
