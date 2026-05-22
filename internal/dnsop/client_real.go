package dnsop

import (
	"fmt"
	"log"
	"net"
	"strconv"
	"strings"
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
		// No response, only an error — try to extract a TSIG-subcode hint
		// from the error message before falling back to a generic
		// "dns-send" classification. bodgit/tsig surfaces BADTIME / BADSIG
		// / BADKEY via the err string; pattern-matching is brittle but the
		// diagnosability win is large (operators see "clock skew" instead
		// of "dial tcp …").
		if r, ok := classifyTSIGError(err); ok {
			return r
		}
		return ApplyResult{OK: false, Phase: "dns-send", Message: err.Error(), Retryable: true}
	}
	if resp == nil {
		return ApplyResult{OK: false, Phase: "dns-receive", Message: "nil response", Retryable: true}
	}
	return ClassifyRcode(resp.Rcode)
}

// classifyTSIGError matches well-known TSIG-subcode substrings in the error
// message and returns a tailored ApplyResult. The matches are case-insensitive
// because different libraries print the codes in different cases.
//
//   - BADTIME: clock skew — retryable, ops should fix NTP on the client or DC.
//   - BADSIG:  TSIG signature mismatch — not retryable, almost always a
//              shared-secret or principal config issue; retrying won't help.
//   - BADKEY:  the server doesn't recognise the key name — not retryable,
//              points at a keytab/principal mismatch or stale GSS context.
func classifyTSIGError(err error) (ApplyResult, bool) {
	msg := err.Error()
	lower := strings.ToLower(msg)
	switch {
	case strings.Contains(lower, "badtime") || strings.Contains(lower, "bad time"):
		return ApplyResult{
			OK:        false,
			Phase:     "tsig-verify",
			Message:   "clock skew between client and DC: " + msg,
			Retryable: true,
		}, true
	case strings.Contains(lower, "badsig") || strings.Contains(lower, "bad signature"):
		return ApplyResult{
			OK:        false,
			Phase:     "tsig-verify",
			Message:   "TSIG signature mismatch (check principal/keytab/realm): " + msg,
			Retryable: false,
		}, true
	case strings.Contains(lower, "badkey") || strings.Contains(lower, "key not found"):
		return ApplyResult{
			OK:        false,
			Phase:     "tsig-verify",
			Message:   "TSIG key not recognised by server (check principal/keytab): " + msg,
			Retryable: false,
		}, true
	}
	return ApplyResult{}, false
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
