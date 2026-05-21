package dnsop

import (
	"fmt"
	"strings"

	"github.com/miekg/dns"
)

// ParseAXFRStream consumes envelopes from an AXFR transfer and returns
// either the complete record set or a typed failure.
//
// Contract (spec §3.4 all-or-nothing):
//   - any envelope with Error != nil → ok:false, records discarded
//   - stream must begin and end with the zone's SOA — anything else → ok:false
//   - SOA records are excluded from the returned slice
//   - returns ok:true only when the trailing SOA is observed
func ParseAXFRStream(ch <-chan *dns.Envelope) RecordsResult {
	var (
		all      []dns.RR
		sawError error
		sawFinal bool
	)
	for env := range ch {
		if env.Error != nil {
			sawError = env.Error
			continue
		}
		all = append(all, env.RR...)
	}
	if sawError != nil {
		return RecordsResult{
			OK:        false,
			Phase:     "dns-receive",
			Message:   sawError.Error(),
			Retryable: true,
		}
	}
	if len(all) < 2 {
		return RecordsResult{
			OK:        false,
			Phase:     "dns-receive",
			Message:   "AXFR stream too short — missing leading or trailing SOA",
			Retryable: true,
		}
	}
	_, firstIsSOA := all[0].(*dns.SOA)
	_, lastIsSOA := all[len(all)-1].(*dns.SOA)
	sawFinal = firstIsSOA && lastIsSOA
	if !sawFinal {
		return RecordsResult{
			OK:        false,
			Phase:     "dns-receive",
			Message:   "AXFR stream did not terminate with SOA",
			Retryable: true,
		}
	}

	out := make([]Record, 0, len(all))
	for i, rr := range all {
		if _, ok := rr.(*dns.SOA); ok {
			// Exclude both bracketing SOAs.
			if i == 0 || i == len(all)-1 {
				continue
			}
		}
		rec, ok := rrToRecord(rr)
		if !ok {
			continue // unsupported types silently skipped (e.g. RRSIG, DNSKEY)
		}
		out = append(out, rec)
	}
	return RecordsResult{OK: true, Records: out}
}

func rrToRecord(rr dns.RR) (Record, bool) {
	hdr := rr.Header()
	rec := Record{
		Name: strings.TrimSuffix(strings.ToLower(hdr.Name), "."),
		TTL:  int(hdr.Ttl),
	}
	switch v := rr.(type) {
	case *dns.A:
		rec.Type = "A"
		rec.Value = v.A.String()
	case *dns.AAAA:
		rec.Type = "AAAA"
		rec.Value = v.AAAA.String()
	case *dns.CNAME:
		rec.Type = "CNAME"
		rec.Value = strings.ToLower(v.Target)
	case *dns.MX:
		rec.Type = "MX"
		rec.Value = fmt.Sprintf("%d %s", v.Preference, strings.ToLower(v.Mx))
	case *dns.NS:
		rec.Type = "NS"
		rec.Value = strings.ToLower(v.Ns)
	case *dns.TXT:
		rec.Type = "TXT"
		// Reassemble TXT chunks into a single quoted string for the wire contract.
		rec.Value = "\"" + strings.Join(v.Txt, "") + "\""
	default:
		return Record{}, false
	}
	return rec, true
}
