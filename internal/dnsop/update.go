package dnsop

import (
	"fmt"
	"strings"

	"github.com/miekg/dns"
)

// BuildUpdateMsg constructs an RFC 2136 UPDATE message with prerequisites
// (placed in the Answer section per RFC 2136 §2.4) and updates (placed in
// the Authority section per §2.5).
func BuildUpdateMsg(zone string, prereqs []Prereq, changes []Change) (*dns.Msg, error) {
	m := new(dns.Msg)
	m.SetUpdate(dns.Fqdn(zone))

	for _, p := range prereqs {
		rr, err := buildPrereqRR(p)
		if err != nil {
			return nil, err
		}
		m.Answer = append(m.Answer, rr)
	}

	for _, c := range changes {
		rr, err := recordToRR(c.Record)
		if err != nil {
			return nil, err
		}
		switch c.Op {
		case "add":
			// "Add to an RRset" — class IN with normal TTL/RDATA.
			m.Ns = append(m.Ns, rr)
		case "delete":
			// "Delete an RR from an RRset" — class NONE, TTL=0.
			rr.Header().Class = dns.ClassNONE
			rr.Header().Ttl = 0
			m.Ns = append(m.Ns, rr)
		default:
			return nil, fmt.Errorf("unknown change op: %s", c.Op)
		}
	}
	return m, nil
}

func buildPrereqRR(p Prereq) (dns.RR, error) {
	rtype, ok := dns.StringToType[strings.ToUpper(p.Type)]
	if !ok {
		return nil, fmt.Errorf("unknown record type in prereq: %s", p.Type)
	}
	hdr := dns.RR_Header{Name: dns.Fqdn(p.Name), Rrtype: rtype, Ttl: 0}
	switch p.Kind {
	case "NXRRSET":
		// "Name is not in use" / "RRset does not exist" — class NONE, TTL 0, no RDATA.
		hdr.Class = dns.ClassNONE
		return &dns.ANY{Hdr: hdr}, nil
	case "YXRRSET":
		// "RRset exists (value dependent)" — class IN with RDATA matching the desired value.
		hdr.Class = dns.ClassINET
		if p.Value == "" {
			return nil, fmt.Errorf("YXRRSET prereq requires value")
		}
		// Build a one-line zone file fragment and parse it.
		s := fmt.Sprintf("%s 0 IN %s %s", hdr.Name, p.Type, p.Value)
		rr, err := dns.NewRR(s)
		if err != nil {
			return nil, fmt.Errorf("parse YXRRSET value: %w", err)
		}
		return rr, nil
	default:
		return nil, fmt.Errorf("unknown prereq kind: %s", p.Kind)
	}
}

func recordToRR(r Record) (dns.RR, error) {
	s := fmt.Sprintf("%s %d IN %s %s", dns.Fqdn(r.Name), r.TTL, r.Type, r.Value)
	rr, err := dns.NewRR(s)
	if err != nil {
		return nil, fmt.Errorf("parse RR %q: %w", s, err)
	}
	return rr, nil
}

// ClassifyRcode maps a DNS rcode int to the wire-contract ApplyResult.
func ClassifyRcode(rcode int) ApplyResult {
	switch rcode {
	case dns.RcodeSuccess:
		return ApplyResult{OK: true, Rcode: "NOERROR"}
	case dns.RcodeServerFailure:
		return ApplyResult{OK: false, Rcode: "SERVFAIL", Phase: "dns-receive", Message: "server failure", Retryable: true}
	case dns.RcodeYXRrset:
		return ApplyResult{OK: false, Rcode: "YXRRSET", Phase: "dns-receive", Message: "prerequisite YXRRSET failed", Retryable: false}
	case dns.RcodeNXRrset:
		return ApplyResult{OK: false, Rcode: "NXRRSET", Phase: "dns-receive", Message: "prerequisite NXRRSET failed", Retryable: false}
	case dns.RcodeNotAuth:
		return ApplyResult{OK: false, Rcode: "NOTAUTH", Phase: "dns-receive", Message: "not authoritative", Retryable: false}
	case dns.RcodeNotZone:
		return ApplyResult{OK: false, Rcode: "NOTZONE", Phase: "dns-receive", Message: "not zone", Retryable: false}
	case dns.RcodeRefused:
		return ApplyResult{OK: false, Rcode: "REFUSED", Phase: "dns-receive", Message: "refused", Retryable: false}
	case dns.RcodeFormatError:
		return ApplyResult{OK: false, Rcode: "FORMERR", Phase: "dns-receive", Message: "format error", Retryable: false}
	default:
		return ApplyResult{OK: false, Rcode: dns.RcodeToString[rcode], Phase: "dns-receive", Message: fmt.Sprintf("unexpected rcode %d", rcode), Retryable: false}
	}
}
