package dnsop

import (
	"net"
	"strconv"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// serveAXFR starts an in-process authoritative server that answers one AXFR
// with the given records. tsigSecret enables TSIG on the server; empty means
// the server signs nothing — which is what Windows DNS does for zone
// transfers.
func serveAXFR(t *testing.T, zone string, rrs []dns.RR, tsigKeyName, tsigSecret string) string {
	t.Helper()

	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	mux := dns.NewServeMux()
	mux.HandleFunc(zone, func(w dns.ResponseWriter, r *dns.Msg) {
		tr := new(dns.Transfer)
		ch := make(chan *dns.Envelope, 1)
		ch <- &dns.Envelope{RR: rrs}
		close(ch)
		_ = tr.Out(w, r, ch)
	})

	srv := &dns.Server{Listener: l, Net: "tcp", Handler: mux}
	if tsigSecret != "" {
		srv.TsigSecret = map[string]string{tsigKeyName: tsigSecret}
	}
	go func() { _ = srv.ActivateAndServe() }()
	t.Cleanup(func() { _ = srv.Shutdown() })

	return l.Addr().String()
}

func zoneRRs(t *testing.T) []dns.RR {
	t.Helper()
	soa, err := dns.NewRR("example.com. 3600 IN SOA ns1.example.com. admin.example.com. 1 7200 3600 1209600 3600")
	if err != nil {
		t.Fatalf("soa: %v", err)
	}
	a, err := dns.NewRR("app.example.com. 60 IN A 10.0.0.5")
	if err != nil {
		t.Fatalf("a: %v", err)
	}
	// AXFR must open and close with the zone's SOA.
	return []dns.RR{soa, a, soa}
}

func hostPort(t *testing.T, addr string) (string, int) {
	t.Helper()
	h, p, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatalf("split: %v", err)
	}
	port, err := strconv.Atoi(p)
	if err != nil {
		t.Fatalf("port: %v", err)
	}
	return h, port
}

// REGRESSION GUARD. Windows DNS does not sign zone transfers: it has no TSIG
// setting for XFR anywhere (GUI, PowerShell, registry, the Dns-Zone AD schema)
// and authorises them by IP ACL alone. Verified on the wire against a live DC —
// an AXFR carrying no TSIG at all returns the full zone, NOERROR.
//
// miekg/dns >= 1.1.72 verifies EVERY envelope whenever a TsigProvider is set
// (#1649, closing a real hole where a server could just omit the TSIG and the
// client would accept it unverified). Passing a provider here therefore aborts
// the transfer with "dns: no signature found" — which is exactly what shipped
// in 0.3.0 and broke production.
//
// So the gss-tsig AXFR path must NOT set a TsigProvider. This test fails if
// anyone puts one back.
func TestRealClient_AXFR_SucceedsAgainstServerThatSignsNothing(t *testing.T) {
	addr := serveAXFR(t, "example.com.", zoneRRs(t), "", "")
	host, port := hostPort(t, addr)

	c := &RealClient{AxfrTimeout: 3 * time.Second, UpdateTimeout: 3 * time.Second}
	res := c.AXFR(host, port, "example.com")

	if !res.OK {
		t.Fatalf("AXFR against an unsigned server must succeed (Windows DNS never signs transfers), got %+v", res)
	}
	if len(res.Records) != 1 || res.Records[0].Name != "app.example.com" {
		t.Fatalf("records: %+v", res.Records)
	}
}

// The gss-tsig client must not need a GSS context for a read. Constructing it
// with a nil GSS and still transferring proves AXFR no longer negotiates one —
// it used to, once per zone per cycle, for a signature the server never sent.
func TestRealClient_AXFR_NeedsNoGSSContext(t *testing.T) {
	addr := serveAXFR(t, "example.com.", zoneRRs(t), "", "")
	host, port := hostPort(t, addr)

	c := &RealClient{GSS: nil, AxfrTimeout: 3 * time.Second}
	if res := c.AXFR(host, port, "example.com"); !res.OK {
		t.Fatalf("AXFR must not touch the GSS context, got %+v", res)
	}
}

// hmac-tsig is the opposite case: BIND, Knot, PowerDNS and Technitium do sign
// transfers, so that path keeps its provider and verifies.
func TestTSIGClient_AXFR_VerifiesSignedTransfer(t *testing.T) {
	const key, secret = "ddo.", "c2VjcmV0"
	addr := serveAXFR(t, "example.com.", zoneRRs(t), key, secret)
	host, port := hostPort(t, addr)

	c := NewTSIGClient(key, secret, dns.HmacSHA256, false, 3*time.Second, 3*time.Second)
	res := c.AXFR(host, port, "example.com")

	if !res.OK {
		t.Fatalf("signed AXFR must verify and succeed, got %+v", res)
	}
	if len(res.Records) != 1 {
		t.Fatalf("records: %+v", res.Records)
	}
}
