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
	if res.Records[0].Value != "10 smtp.example.com" {
		t.Fatalf("expected MX value with priority and dot-stripped host, got %q", res.Records[0].Value)
	}
}

// Round-trip idempotency: operator stores hostname targets without a trailing dot
// (CNAME "host.example.com", NS "ns1.example.com", MX "10 smtp.example.com");
// AD stores them canonically with the dot. If we surface the dotted form on read,
// the operator's string-compare diff sees drift every cycle. Strip on read only.
func TestParseAXFRStream_StripsTrailingDotOnHostnameTargets(t *testing.T) {
	soa := mustSOA(t, "example.com. 3600 IN SOA ns1.example.com. host.example.com. 1 900 600 86400 3600")
	cname, err := dns.NewRR("alias.example.com. 3600 IN CNAME target.example.com.")
	if err != nil {
		t.Fatal(err)
	}
	ns, err := dns.NewRR("sub.example.com. 3600 IN NS ns1.example.com.")
	if err != nil {
		t.Fatal(err)
	}
	mx, err := dns.NewRR("mail.example.com. 3600 IN MX 10 smtp.example.com.")
	if err != nil {
		t.Fatal(err)
	}
	// A records must NOT be touched — IP literals have no trailing-dot semantics.
	a := mustA(t, "host.example.com. 300 IN A 192.0.2.20")

	xfer := fakeXfer{envelopes: []*dns.Envelope{
		{RR: []dns.RR{soa, cname, ns, mx, a, soa}, Error: nil},
	}}
	res := ParseAXFRStream(xfer.Stream())
	if !res.OK || len(res.Records) != 4 {
		t.Fatalf("bad: %+v", res)
	}

	got := map[string]string{}
	for _, r := range res.Records {
		got[r.Type] = r.Value
	}
	want := map[string]string{
		"CNAME": "target.example.com",
		"NS":    "ns1.example.com",
		"MX":    "10 smtp.example.com",
		"A":     "192.0.2.20",
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s value: got %q, want %q", k, got[k], v)
		}
	}
}

func TestRRToRecord_TrailingDotEdgeCases(t *testing.T) {
	// Root "." and empty/multi-dot must not be mangled. dns.NewRR can't
	// build a CNAME with empty target, so we exercise the helper directly
	// with synthetic dns.RR values.
	cases := []struct {
		name string
		rr   dns.RR
		want string
	}{
		{
			name: "cname single trailing dot stripped",
			rr:   &dns.CNAME{Hdr: dns.RR_Header{Name: "a.example.com.", Rrtype: dns.TypeCNAME, Ttl: 60}, Target: "b.example.com."},
			want: "b.example.com",
		},
		{
			name: "cname no trailing dot left alone",
			rr:   &dns.CNAME{Hdr: dns.RR_Header{Name: "a.example.com.", Rrtype: dns.TypeCNAME, Ttl: 60}, Target: "b.example.com"},
			want: "b.example.com",
		},
		{
			name: "cname root target preserved as empty",
			rr:   &dns.CNAME{Hdr: dns.RR_Header{Name: "a.example.com.", Rrtype: dns.TypeCNAME, Ttl: 60}, Target: "."},
			want: "",
		},
		{
			name: "ns trailing dot stripped",
			rr:   &dns.NS{Hdr: dns.RR_Header{Name: "sub.example.com.", Rrtype: dns.TypeNS, Ttl: 60}, Ns: "ns1.example.com."},
			want: "ns1.example.com",
		},
		{
			name: "mx single trailing dot stripped",
			rr:   &dns.MX{Hdr: dns.RR_Header{Name: "mail.example.com.", Rrtype: dns.TypeMX, Ttl: 60}, Preference: 20, Mx: "smtp.example.com."},
			want: "20 smtp.example.com",
		},
		{
			name: "mx no trailing dot left alone, priority preserved",
			rr:   &dns.MX{Hdr: dns.RR_Header{Name: "mail.example.com.", Rrtype: dns.TypeMX, Ttl: 60}, Preference: 5, Mx: "smtp.example.com"},
			want: "5 smtp.example.com",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec, ok := rrToRecord(tc.rr)
			if !ok {
				t.Fatalf("rrToRecord returned !ok for %T", tc.rr)
			}
			if rec.Value != tc.want {
				t.Errorf("value: got %q, want %q", rec.Value, tc.want)
			}
		})
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
