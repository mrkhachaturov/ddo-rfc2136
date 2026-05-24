package orchestrator

import (
	"context"
	"strings"
	"sync"
	"testing"

	"github.com/mrkhachaturov/ddo-rfc2136/internal/dnsop"
)

// fakeClient is a deterministic dnsop.Client for unit tests. Each call type
// reads from queued responses; if empty, returns the default.
type fakeClient struct {
	mu sync.Mutex

	axfrByDCZone   map[string]dnsop.RecordsResult
	updateByDCZone map[string]dnsop.ApplyResult
	defaultAXFR    dnsop.RecordsResult
	defaultUpdate  dnsop.ApplyResult

	axfrCalls   []string
	updateCalls []updateCall
}

type updateCall struct {
	dc, zone string
	prereqs  []dnsop.Prereq
	changes  []dnsop.Change
}

func newFakeClient() *fakeClient {
	return &fakeClient{
		axfrByDCZone:   map[string]dnsop.RecordsResult{},
		updateByDCZone: map[string]dnsop.ApplyResult{},
		defaultAXFR:    dnsop.RecordsResult{OK: true},
		defaultUpdate:  dnsop.ApplyResult{OK: true},
	}
}

func (f *fakeClient) AXFR(host string, port int, zone string) dnsop.RecordsResult {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.axfrCalls = append(f.axfrCalls, host+"|"+zone)
	if r, ok := f.axfrByDCZone[host+"|"+zone]; ok {
		return r
	}
	return f.defaultAXFR
}

func (f *fakeClient) Update(host string, port int, zone string, prereqs []dnsop.Prereq, changes []dnsop.Change) dnsop.ApplyResult {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.updateCalls = append(f.updateCalls, updateCall{dc: host, zone: zone, prereqs: prereqs, changes: changes})
	if r, ok := f.updateByDCZone[host+"|"+zone]; ok {
		return r
	}
	return f.defaultUpdate
}

func defaultOpts() Options {
	return Options{
		Hosts:                   []string{"dc01.corp.example.com", "dc02.corp.example.com"},
		Port:                    53,
		Zones:                   []string{"corp.example.com"},
		AxfrEnabled:             true,
		DefaultTTL:              3600,
		MinTTL:                  60,
		CircuitBreakerThreshold: 3,
		OwnershipLabel:          "docker-dns-operator:1",
	}
}

func ownershipRecord(name, dataType, label string) dnsop.Record {
	return dnsop.Record{
		Name:  "ddo-" + strings.ToLower(dataType) + "." + name,
		Type:  "TXT",
		TTL:   3600,
		Value: `"owned-by=` + label + `"`,
	}
}

// -- ListRecords -----------------------------------------------------------

func TestListRecords_OnlyOwnedRecordsEmitted(t *testing.T) {
	fc := newFakeClient()
	fc.axfrByDCZone["dc01.corp.example.com|corp.example.com"] = dnsop.RecordsResult{
		OK: true,
		Records: []dnsop.Record{
			{Name: "owned.corp.example.com", Type: "A", TTL: 300, Value: "10.0.0.1"},
			ownershipRecord("owned.corp.example.com", "A", "docker-dns-operator:1"),
			{Name: "unowned.corp.example.com", Type: "A", TTL: 300, Value: "10.0.0.2"},
			{Name: "owned-by-other.corp.example.com", Type: "A", TTL: 300, Value: "10.0.0.3"},
			ownershipRecord("owned-by-other.corp.example.com", "A", "other-op:1"),
		},
	}
	o := New(defaultOpts(), fc)
	eps, err := o.ListRecords(context.Background())
	if err != nil {
		t.Fatalf("ListRecords: %v", err)
	}
	if len(eps) != 1 {
		t.Fatalf("expected exactly 1 endpoint, got %d: %+v", len(eps), eps)
	}
	if eps[0].DNSName != "owned.corp.example.com" || eps[0].Labels["owner"] != "docker-dns-operator:1" {
		t.Fatalf("bad endpoint: %+v", eps[0])
	}
}

func TestListRecords_AxfrDisabledReturnsEmpty(t *testing.T) {
	fc := newFakeClient()
	opts := defaultOpts()
	opts.AxfrEnabled = false
	o := New(opts, fc)
	eps, err := o.ListRecords(context.Background())
	if err != nil {
		t.Fatalf("ListRecords: %v", err)
	}
	if len(eps) != 0 {
		t.Fatalf("expected empty list, got %+v", eps)
	}
	if len(fc.axfrCalls) != 0 {
		t.Fatalf("expected no AXFR calls when disabled, got %v", fc.axfrCalls)
	}
}

func TestListRecords_DCFailoverOnAXFRError(t *testing.T) {
	fc := newFakeClient()
	fc.axfrByDCZone["dc01.corp.example.com|corp.example.com"] = dnsop.RecordsResult{
		OK: false, Phase: "dns-send", Message: "down", Retryable: true,
	}
	fc.axfrByDCZone["dc02.corp.example.com|corp.example.com"] = dnsop.RecordsResult{
		OK:      true,
		Records: []dnsop.Record{}, // empty zone is fine
	}
	o := New(defaultOpts(), fc)
	if _, err := o.ListRecords(context.Background()); err != nil {
		t.Fatalf("ListRecords: %v", err)
	}
	// Both DCs were tried.
	if len(fc.axfrCalls) != 2 {
		t.Fatalf("expected 2 AXFR attempts, got %v", fc.axfrCalls)
	}
	// dc02 should now be pinned.
	dc, ok := o.pins.Get("corp.example.com")
	if !ok || dc != "dc02.corp.example.com" {
		t.Fatalf("expected pin to dc02, got dc=%q ok=%v", dc, ok)
	}
}

func TestListRecords_CoalescesConcurrentCallers(t *testing.T) {
	// Each goroutine calls ListRecords once; we want the total AXFR count
	// to equal N (number of zones × number of calls). Because axfrMu
	// serialises calls but does not de-duplicate them, we expect N=zones
	// per caller call. The point of this test is to assert "serialised
	// access, no torn state" rather than "single shared fetch".
	fc := newFakeClient()
	o := New(defaultOpts(), fc)
	var wg sync.WaitGroup
	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _ = o.ListRecords(context.Background())
		}()
	}
	wg.Wait()
	if len(fc.axfrCalls) != 5 {
		t.Fatalf("expected 5 sequential AXFR calls (1 zone × 5 callers), got %d", len(fc.axfrCalls))
	}
}

// -- ApplyChanges ----------------------------------------------------------

func TestApplyChanges_CreateBuildsOwnershipTxt(t *testing.T) {
	fc := newFakeClient()
	o := New(defaultOpts(), fc)
	_, _ = o.ListRecords(context.Background()) // prime cache (empty)
	err := o.ApplyChanges(context.Background(), Changes{
		Create: []*Endpoint{{
			DNSName: "app.corp.example.com", RecordType: "A", RecordTTL: 300, Targets: []string{"10.1.2.3"},
		}},
	})
	if err != nil {
		t.Fatalf("ApplyChanges: %v", err)
	}
	if len(fc.updateCalls) != 1 {
		t.Fatalf("expected 1 UPDATE, got %d", len(fc.updateCalls))
	}
	c := fc.updateCalls[0]
	if len(c.prereqs) != 2 {
		t.Fatalf("expected 2 prereqs (NXRRSET data + NXRRSET TXT), got %+v", c.prereqs)
	}
	if len(c.changes) != 2 {
		t.Fatalf("expected 2 changes (data + TXT), got %+v", c.changes)
	}
	// One of the changes must be the ownership TXT.
	sawTxt := false
	for _, ch := range c.changes {
		if ch.Record.Type == "TXT" && strings.HasPrefix(ch.Record.Name, "ddo-a.") {
			sawTxt = true
			if ch.Record.Value != `"owned-by=docker-dns-operator:1"` {
				t.Fatalf("ownership txt value: %q", ch.Record.Value)
			}
		}
	}
	if !sawTxt {
		t.Fatalf("missing ownership txt change in %+v", c.changes)
	}
}

func TestApplyChanges_CreateSkipsTxtPrereqOnOrphan(t *testing.T) {
	fc := newFakeClient()
	// Pre-seed cache: ownership TXT exists but data record doesn't (orphan).
	fc.axfrByDCZone["dc01.corp.example.com|corp.example.com"] = dnsop.RecordsResult{
		OK: true,
		Records: []dnsop.Record{
			ownershipRecord("app.corp.example.com", "A", "docker-dns-operator:1"),
		},
	}
	o := New(defaultOpts(), fc)
	if _, err := o.ListRecords(context.Background()); err != nil {
		t.Fatalf("prime: %v", err)
	}
	if err := o.ApplyChanges(context.Background(), Changes{
		Create: []*Endpoint{{DNSName: "app.corp.example.com", RecordType: "A", RecordTTL: 300, Targets: []string{"10.1.2.3"}}},
	}); err != nil {
		t.Fatalf("ApplyChanges: %v", err)
	}
	c := fc.updateCalls[0]
	// Only the data NXRRSET prereq, plus exactly one change (data add). TXT
	// prereq and TXT add are both skipped because the TXT already exists.
	if len(c.prereqs) != 1 {
		t.Fatalf("expected 1 prereq when orphan TXT present, got %+v", c.prereqs)
	}
	if len(c.changes) != 1 {
		t.Fatalf("expected 1 change when orphan TXT present, got %+v", c.changes)
	}
}

func TestApplyChanges_CreateSkippedOnCnameCollision(t *testing.T) {
	fc := newFakeClient()
	// Pre-seed cache with an A record at the name. CNAME create must be refused.
	fc.axfrByDCZone["dc01.corp.example.com|corp.example.com"] = dnsop.RecordsResult{
		OK: true,
		Records: []dnsop.Record{
			{Name: "app.corp.example.com", Type: "A", TTL: 300, Value: "10.1.2.3"},
			ownershipRecord("app.corp.example.com", "A", "docker-dns-operator:1"),
		},
	}
	o := New(defaultOpts(), fc)
	if _, err := o.ListRecords(context.Background()); err != nil {
		t.Fatalf("prime: %v", err)
	}
	if err := o.ApplyChanges(context.Background(), Changes{
		Create: []*Endpoint{{DNSName: "app.corp.example.com", RecordType: "CNAME", RecordTTL: 300, Targets: []string{"target.corp.example.com"}}},
	}); err != nil {
		t.Fatalf("ApplyChanges: %v", err)
	}
	if len(fc.updateCalls) != 0 {
		t.Fatalf("expected NO UPDATE on collision, got %d", len(fc.updateCalls))
	}
}

func TestApplyChanges_CreateSkippedOnUnownedSameType(t *testing.T) {
	fc := newFakeClient()
	// Existing A record at the name with no ownership TXT — collision.
	fc.axfrByDCZone["dc01.corp.example.com|corp.example.com"] = dnsop.RecordsResult{
		OK: true,
		Records: []dnsop.Record{
			{Name: "app.corp.example.com", Type: "A", TTL: 300, Value: "10.99.99.99"},
		},
	}
	o := New(defaultOpts(), fc)
	if _, err := o.ListRecords(context.Background()); err != nil {
		t.Fatalf("prime: %v", err)
	}
	if err := o.ApplyChanges(context.Background(), Changes{
		Create: []*Endpoint{{DNSName: "app.corp.example.com", RecordType: "A", RecordTTL: 300, Targets: []string{"10.1.2.3"}}},
	}); err != nil {
		t.Fatalf("ApplyChanges: %v", err)
	}
	if len(fc.updateCalls) != 0 {
		t.Fatalf("expected NO UPDATE on unowned same-type collision, got %d", len(fc.updateCalls))
	}
}

func TestApplyChanges_DeleteIncludesTxtPrereqAndDelete(t *testing.T) {
	fc := newFakeClient()
	o := New(defaultOpts(), fc)
	if _, err := o.ListRecords(context.Background()); err != nil {
		t.Fatalf("prime: %v", err)
	}
	if err := o.ApplyChanges(context.Background(), Changes{
		Delete: []*Endpoint{{DNSName: "app.corp.example.com", RecordType: "A", RecordTTL: 300, Targets: []string{"10.1.2.3"}}},
	}); err != nil {
		t.Fatalf("ApplyChanges: %v", err)
	}
	c := fc.updateCalls[0]
	if len(c.prereqs) != 1 || c.prereqs[0].Kind != "YXRRSET" {
		t.Fatalf("expected single YXRRSET prereq, got %+v", c.prereqs)
	}
	if len(c.changes) != 2 {
		t.Fatalf("expected delete-data + delete-TXT, got %+v", c.changes)
	}
}

func TestApplyChanges_UpdateKeepsTxtUntouched(t *testing.T) {
	fc := newFakeClient()
	o := New(defaultOpts(), fc)
	if _, err := o.ListRecords(context.Background()); err != nil {
		t.Fatalf("prime: %v", err)
	}
	old := &Endpoint{DNSName: "app.corp.example.com", RecordType: "A", RecordTTL: 300, Targets: []string{"10.0.0.1"}}
	upd := &Endpoint{DNSName: "app.corp.example.com", RecordType: "A", RecordTTL: 300, Targets: []string{"10.0.0.2"}}
	if err := o.ApplyChanges(context.Background(), Changes{
		UpdateOld: []*Endpoint{old},
		UpdateNew: []*Endpoint{upd},
	}); err != nil {
		t.Fatalf("ApplyChanges: %v", err)
	}
	c := fc.updateCalls[0]
	if len(c.prereqs) != 1 || c.prereqs[0].Kind != "YXRRSET" {
		t.Fatalf("expected single YXRRSET prereq, got %+v", c.prereqs)
	}
	// One delete (old) + one add (new), no TXT change.
	if len(c.changes) != 2 {
		t.Fatalf("expected 2 changes (delete + add), got %+v", c.changes)
	}
	for _, ch := range c.changes {
		if ch.Record.Type == "TXT" {
			t.Fatalf("update must NOT touch the ownership TXT, saw %+v", ch)
		}
	}
}

func TestApplyChanges_DomainFilterSkips(t *testing.T) {
	fc := newFakeClient()
	opts := defaultOpts()
	opts.DomainFilter = []string{"svc.corp.example.com"}
	o := New(opts, fc)
	_, _ = o.ListRecords(context.Background())
	if err := o.ApplyChanges(context.Background(), Changes{
		Create: []*Endpoint{{DNSName: "outside.corp.example.com", RecordType: "A", RecordTTL: 300, Targets: []string{"10.0.0.1"}}},
	}); err != nil {
		t.Fatalf("ApplyChanges: %v", err)
	}
	if len(fc.updateCalls) != 0 {
		t.Fatalf("domain-filtered endpoint must be skipped, got %d UPDATEs", len(fc.updateCalls))
	}
}

func TestApplyChanges_NoMatchingZoneSkips(t *testing.T) {
	fc := newFakeClient()
	o := New(defaultOpts(), fc)
	if err := o.ApplyChanges(context.Background(), Changes{
		Create: []*Endpoint{{DNSName: "host.other.example.com", RecordType: "A", RecordTTL: 300, Targets: []string{"10.0.0.1"}}},
	}); err != nil {
		t.Fatalf("ApplyChanges: %v", err)
	}
	if len(fc.updateCalls) != 0 {
		t.Fatalf("unmatched zone must be skipped")
	}
}

func TestApplyChanges_DryRunSkipsUpdate(t *testing.T) {
	fc := newFakeClient()
	opts := defaultOpts()
	opts.DryRun = true
	o := New(opts, fc)
	_, _ = o.ListRecords(context.Background())
	if err := o.ApplyChanges(context.Background(), Changes{
		Create: []*Endpoint{{DNSName: "app.corp.example.com", RecordType: "A", RecordTTL: 300, Targets: []string{"10.1.2.3"}}},
	}); err != nil {
		t.Fatalf("ApplyChanges: %v", err)
	}
	if len(fc.updateCalls) != 0 {
		t.Fatalf("dry-run must NOT call UPDATE")
	}
}

func TestApplyChanges_FailoverOnRetryable(t *testing.T) {
	fc := newFakeClient()
	fc.updateByDCZone["dc01.corp.example.com|corp.example.com"] = dnsop.ApplyResult{
		OK: false, Rcode: "SERVFAIL", Phase: "dns-receive", Retryable: true,
	}
	o := New(defaultOpts(), fc)
	_, _ = o.ListRecords(context.Background())
	if err := o.ApplyChanges(context.Background(), Changes{
		Create: []*Endpoint{{DNSName: "app.corp.example.com", RecordType: "A", RecordTTL: 300, Targets: []string{"10.1.2.3"}}},
	}); err != nil {
		t.Fatalf("ApplyChanges: %v", err)
	}
	if len(fc.updateCalls) != 2 {
		t.Fatalf("expected fail-then-success across 2 DCs, got %d", len(fc.updateCalls))
	}
	dc, ok := o.pins.Get("corp.example.com")
	if !ok || dc != "dc02.corp.example.com" {
		t.Fatalf("expected pin to dc02 after failover, got %q", dc)
	}
}

func TestApplyChanges_NoFailoverOnNonRetryable(t *testing.T) {
	fc := newFakeClient()
	fc.updateByDCZone["dc01.corp.example.com|corp.example.com"] = dnsop.ApplyResult{
		OK: false, Rcode: "NXRRSET", Phase: "dns-receive", Retryable: false,
	}
	fc.updateByDCZone["dc02.corp.example.com|corp.example.com"] = dnsop.ApplyResult{OK: true}
	o := New(defaultOpts(), fc)
	_, _ = o.ListRecords(context.Background())
	err := o.ApplyChanges(context.Background(), Changes{
		Create: []*Endpoint{{DNSName: "app.corp.example.com", RecordType: "A", RecordTTL: 300, Targets: []string{"10.1.2.3"}}},
	})
	if err == nil {
		t.Fatalf("expected error on non-retryable failure")
	}
	if len(fc.updateCalls) != 1 {
		t.Fatalf("non-retryable must NOT failover, got %d UPDATEs", len(fc.updateCalls))
	}
}

// -- routing & filters -----------------------------------------------------

func TestZoneFor_LongestSuffixWins(t *testing.T) {
	o := New(Options{Zones: []string{"example.com", "corp.example.com"}}, newFakeClient())
	got := o.zoneFor("host.corp.example.com.")
	if got != "corp.example.com" {
		t.Fatalf("longest suffix: got %q", got)
	}
}

func TestZoneFor_NoMatch(t *testing.T) {
	o := New(Options{Zones: []string{"example.com"}}, newFakeClient())
	if got := o.zoneFor("host.other.net"); got != "" {
		t.Fatalf("expected no match, got %q", got)
	}
}

func TestDomainFilter_MatchesByExactAndSuffix(t *testing.T) {
	o := New(Options{DomainFilter: []string{"svc.corp.example.com"}}, newFakeClient())
	if !o.matchesDomainFilter("svc.corp.example.com") {
		t.Fatalf("exact match should pass")
	}
	if !o.matchesDomainFilter("api.svc.corp.example.com.") {
		t.Fatalf("dotted suffix should pass")
	}
	if o.matchesDomainFilter("other.corp.example.com") {
		t.Fatalf("non-matching should fail")
	}
}

func TestEndpointToRecords_MXEncoding(t *testing.T) {
	o := New(defaultOpts(), newFakeClient())
	recs := o.endpointToRecords(&Endpoint{
		DNSName: "mail.corp.example.com", RecordType: "MX", RecordTTL: 300,
		Targets: []string{"10 smtp.corp.example.com"},
	})
	if len(recs) != 1 || recs[0].Value != "10 smtp.corp.example.com." {
		t.Fatalf("MX encoding: %+v", recs)
	}
}

func TestEndpointToRecords_CNAMEAppendsDot(t *testing.T) {
	o := New(defaultOpts(), newFakeClient())
	recs := o.endpointToRecords(&Endpoint{
		DNSName: "alias.corp.example.com", RecordType: "CNAME", RecordTTL: 300,
		Targets: []string{"Real.corp.example.com"},
	})
	if len(recs) != 1 || recs[0].Value != "real.corp.example.com." {
		t.Fatalf("CNAME canonical form: %+v", recs)
	}
}

func TestEndpointToRecords_TTLClampedToMin(t *testing.T) {
	opts := defaultOpts()
	opts.MinTTL = 120
	o := New(opts, newFakeClient())
	recs := o.endpointToRecords(&Endpoint{
		DNSName: "x.corp.example.com", RecordType: "A", RecordTTL: 30, Targets: []string{"10.1.1.1"},
	})
	if recs[0].TTL != 120 {
		t.Fatalf("expected TTL clamp to MinTTL=120, got %d", recs[0].TTL)
	}
}

func TestEndpointToRecords_TTLDefaultWhenZero(t *testing.T) {
	o := New(defaultOpts(), newFakeClient())
	recs := o.endpointToRecords(&Endpoint{
		DNSName: "x.corp.example.com", RecordType: "A", RecordTTL: 0, Targets: []string{"10.1.1.1"},
	})
	if recs[0].TTL != 3600 {
		t.Fatalf("expected DefaultTTL=3600 fallback, got %d", recs[0].TTL)
	}
}

func TestOrphanOwnership_DetectedAndLogged(t *testing.T) {
	o := New(defaultOpts(), newFakeClient())
	orphans := o.orphanOwnership([]dnsop.Record{
		ownershipRecord("app.corp.example.com", "A", "docker-dns-operator:1"),
		// no sibling A
	})
	if !orphans["ddo-a.app.corp.example.com"] {
		t.Fatalf("expected orphan set to contain TXT, got %+v", orphans)
	}
}

func TestOrphanOwnership_NotDetectedWhenSiblingPresent(t *testing.T) {
	o := New(defaultOpts(), newFakeClient())
	orphans := o.orphanOwnership([]dnsop.Record{
		ownershipRecord("app.corp.example.com", "A", "docker-dns-operator:1"),
		{Name: "app.corp.example.com", Type: "A", TTL: 300, Value: "10.0.0.1"},
	})
	if len(orphans) != 0 {
		t.Fatalf("expected no orphans, got %+v", orphans)
	}
}
