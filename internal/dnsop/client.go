package dnsop

// Client is the DNS-protocol surface the HTTP api needs. Mockable in tests.
type Client interface {
	AXFR(host string, port int, zone string) RecordsResult
	Update(host string, port int, zone string, prereqs []Prereq, changes []Change) ApplyResult
}
