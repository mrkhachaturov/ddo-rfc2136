package dnsop

// Client is the DNS-protocol surface the HTTP api needs. Mockable in tests.
//
// Two implementations differ only in how they sign: RealClient negotiates a
// GSS context per exchange, TSIGClient signs with a pre-shared key or not at
// all. RFC2136_AUTH_MODE picks one at startup.
type Client interface {
	AXFR(host string, port int, zone string) RecordsResult
	Update(host string, port int, zone string, prereqs []Prereq, changes []Change) ApplyResult
}

var (
	_ Client = (*RealClient)(nil)
	_ Client = (*TSIGClient)(nil)
)
