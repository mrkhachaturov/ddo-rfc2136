package dnsop

import (
	"errors"
	"testing"

	"github.com/miekg/dns"
)

type fakeXfer struct {
	envelopes []*dns.Envelope
}

func (f fakeXfer) Stream() <-chan *dns.Envelope {
	ch := make(chan *dns.Envelope, len(f.envelopes))
	for _, e := range f.envelopes {
		ch <- e
	}
	close(ch)
	return ch
}

func mustSOA(t *testing.T, s string) *dns.SOA {
	t.Helper()
	rr, err := dns.NewRR(s)
	if err != nil {
		t.Fatal(err)
	}
	return rr.(*dns.SOA)
}

func mustA(t *testing.T, s string) *dns.A {
	t.Helper()
	rr, err := dns.NewRR(s)
	if err != nil {
		t.Fatal(err)
	}
	return rr.(*dns.A)
}

func TestParseAXFRStream_HappyPath(t *testing.T) {
	soa := mustSOA(t, "example.com. 3600 IN SOA ns1.example.com. host.example.com. 1 900 600 86400 3600")
	a := mustA(t, "a.example.com. 300 IN A 10.0.0.1")
	xfer := fakeXfer{envelopes: []*dns.Envelope{
		{RR: []dns.RR{soa, a, soa}, Error: nil},
	}}
	res := ParseAXFRStream(xfer.Stream())
	if !res.OK {
		t.Fatalf("expected ok, got %+v", res)
	}
	if len(res.Records) != 1 {
		t.Fatalf("expected 1 record (SOA excluded), got %d", len(res.Records))
	}
	if res.Records[0].Type != "A" {
		t.Fatalf("expected A, got %s", res.Records[0].Type)
	}
}

func TestParseAXFRStream_StreamError(t *testing.T) {
	xfer := fakeXfer{envelopes: []*dns.Envelope{
		{RR: nil, Error: errors.New("connection reset")},
	}}
	res := ParseAXFRStream(xfer.Stream())
	if res.OK {
		t.Fatalf("expected !ok on stream error")
	}
	if len(res.Records) != 0 {
		t.Fatalf("expected no records on failure, got %d", len(res.Records))
	}
	if !res.Retryable {
		t.Fatalf("network errors should be retryable")
	}
}

func TestParseAXFRStream_MXIncludesPriority(t *testing.T) {
	soa := mustSOA(t, "example.com. 3600 IN SOA ns1.example.com. host.example.com. 1 900 600 86400 3600")
	mx, err := dns.NewRR("mail.example.com. 3600 IN MX 10 smtp.example.com.")
	if err != nil {
		t.Fatal(err)
	}
	xfer := fakeXfer{envelopes: []*dns.Envelope{
		{RR: []dns.RR{soa, mx, soa}, Error: nil},
	}}
	res := ParseAXFRStream(xfer.Stream())
	if !res.OK || len(res.Records) != 1 {
		t.Fatalf("bad: %+v", res)
	}
	if res.Records[0].Type != "MX" {
		t.Fatalf("expected MX, got %s", res.Records[0].Type)
	}
	if res.Records[0].Value != "10 smtp.example.com." {
		t.Fatalf("expected canonical MX value with priority, got %q", res.Records[0].Value)
	}
}

func TestParseAXFRStream_MissingFinalSOA(t *testing.T) {
	soa := mustSOA(t, "example.com. 3600 IN SOA ns1.example.com. host.example.com. 1 900 600 86400 3600")
	a := mustA(t, "a.example.com. 300 IN A 10.0.0.1")
	xfer := fakeXfer{envelopes: []*dns.Envelope{
		{RR: []dns.RR{soa, a}, Error: nil}, // no trailing SOA
	}}
	res := ParseAXFRStream(xfer.Stream())
	if res.OK {
		t.Fatalf("expected !ok when stream ends without final SOA")
	}
}
