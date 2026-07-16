package dnsop

import (
	"errors"
	"testing"
	"time"

	"github.com/bodgit/tsig"
	"github.com/miekg/dns"
)

func hmacClient() *TSIGClient {
	return NewTSIGClient("ddo.", "c2VjcmV0", dns.HmacSHA256, false, time.Second, time.Second)
}

func TestTSIGClient_SignsWithConfiguredKeyAndAlgorithm(t *testing.T) {
	c := hmacClient()
	m := new(dns.Msg)
	m.SetUpdate("example.com.")

	p := c.sign(m)

	if _, ok := p.(tsig.HMAC); !ok {
		t.Fatalf("provider: got %T want tsig.HMAC", p)
	}
	rr := m.IsTsig()
	if rr == nil {
		t.Fatalf("no TSIG RR attached to the message")
	}
	if rr.Hdr.Name != "ddo." {
		t.Fatalf("TSIG key name: got %q want %q", rr.Hdr.Name, "ddo.")
	}
	if rr.Algorithm != dns.HmacSHA256 {
		t.Fatalf("TSIG algorithm: got %q want %q", rr.Algorithm, dns.HmacSHA256)
	}
	if rr.Fudge != tsigFudge {
		t.Fatalf("TSIG fudge: got %d want %d", rr.Fudge, tsigFudge)
	}
}

// The provider is keyed by name: a mismatch here means the MAC is computed
// with an empty secret and the server answers BADSIG.
func TestTSIGClient_ProviderIsKeyedByKeyName(t *testing.T) {
	c := hmacClient()
	p := c.sign(new(dns.Msg))
	h, ok := p.(tsig.HMAC)
	if !ok {
		t.Fatalf("provider: got %T", p)
	}
	if h["ddo."] != "c2VjcmV0" {
		t.Fatalf("secret not registered under the key name: %+v", h)
	}
}

func TestTSIGClient_InsecureSignsNothing(t *testing.T) {
	c := NewTSIGClient("", "", "", true, time.Second, time.Second)
	m := new(dns.Msg)
	m.SetUpdate("example.com.")

	if p := c.sign(m); p != nil {
		t.Fatalf("insecure mode must not return a TSIG provider, got %T", p)
	}
	if rr := m.IsTsig(); rr != nil {
		t.Fatalf("insecure mode must not attach a TSIG RR, got %v", rr)
	}
}

func TestTSIGClient_UpdateSendsSignedMessageAndClassifies(t *testing.T) {
	c := hmacClient()
	var sentTo string
	var signed bool
	c.exchange = func(_ *dns.Client, m *dns.Msg, addr string) (*dns.Msg, time.Duration, error) {
		sentTo = addr
		signed = m.IsTsig() != nil
		resp := new(dns.Msg)
		resp.Rcode = dns.RcodeSuccess
		return resp, 0, nil
	}

	res := c.Update("10.1.125.10", 53, "example.com", nil, []Change{
		{Op: "add", Record: Record{Name: "app.example.com", Type: "A", TTL: 60, Value: "10.0.0.5"}},
	})

	if !res.OK {
		t.Fatalf("expected OK, got %+v", res)
	}
	if sentTo != "10.1.125.10:53" {
		t.Fatalf("addr: got %q", sentTo)
	}
	if !signed {
		t.Fatalf("UPDATE went out unsigned in hmac-tsig mode")
	}
}

func TestTSIGClient_UpdateInsecureSendsUnsigned(t *testing.T) {
	c := NewTSIGClient("", "", "", true, time.Second, time.Second)
	var signed bool
	c.exchange = func(_ *dns.Client, m *dns.Msg, _ string) (*dns.Msg, time.Duration, error) {
		signed = m.IsTsig() != nil
		resp := new(dns.Msg)
		resp.Rcode = dns.RcodeSuccess
		return resp, 0, nil
	}

	if res := c.Update("10.1.125.10", 53, "example.com", nil, []Change{
		{Op: "add", Record: Record{Name: "app.example.com", Type: "A", TTL: 60, Value: "10.0.0.5"}},
	}); !res.OK {
		t.Fatalf("expected OK, got %+v", res)
	}
	if signed {
		t.Fatalf("insecure mode attached a TSIG RR")
	}
}

// A wrong shared secret surfaces as BADSIG. It must not be retried: the
// signature will be just as wrong next tick.
func TestTSIGClient_UpdateBadSigIsPermanent(t *testing.T) {
	c := hmacClient()
	c.exchange = func(_ *dns.Client, _ *dns.Msg, _ string) (*dns.Msg, time.Duration, error) {
		return nil, 0, errors.New("dns: bad signature (BADSIG)")
	}

	res := c.Update("10.1.125.10", 53, "example.com", nil, []Change{
		{Op: "add", Record: Record{Name: "app.example.com", Type: "A", TTL: 60, Value: "10.0.0.5"}},
	})

	if res.OK {
		t.Fatalf("expected failure")
	}
	if res.Retryable {
		t.Fatalf("BADSIG must not be retryable: %+v", res)
	}
	if res.Phase != "tsig-verify" {
		t.Fatalf("phase: got %q want %q", res.Phase, "tsig-verify")
	}
}

func TestTSIGClient_UpdateRejectsBadPrereq(t *testing.T) {
	c := hmacClient()
	c.exchange = func(_ *dns.Client, _ *dns.Msg, _ string) (*dns.Msg, time.Duration, error) {
		t.Fatalf("exchange must not be reached when the message cannot be built")
		return nil, 0, nil
	}

	res := c.Update("10.1.125.10", 53, "example.com", []Prereq{{Kind: "BOGUS", Name: "a.example.com", Type: "A"}}, nil)

	if res.OK || res.Retryable {
		t.Fatalf("a malformed prereq is a permanent failure: %+v", res)
	}
}
