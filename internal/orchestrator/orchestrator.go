// Package orchestrator owns the high-level RFC2136 logic that the operator
// used to drive over the wire: per-cycle AXFR, DC failover with circuit
// breaking, per-zone serialisation, ownership-TXT bridging to the
// external-dns webhook Endpoint shape, and collision detection.
//
// The HTTP handler layer translates external-dns webhook v1 requests into
// calls on this package; the dnsop layer owns the low-level DNS protocol
// (AXFR stream parsing, UPDATE message building, GSS-TSIG).
package orchestrator

import (
	"context"
	"errors"
	"fmt"
	"log"
	"sort"
	"strings"
	"sync"

	"github.com/mrkhachaturov/ddo-rfc2136/internal/dnsop"
	"github.com/mrkhachaturov/ddo-rfc2136/internal/state"
)

// Options configures an Orchestrator. All fields are required.
type Options struct {
	Hosts                   []string
	Port                    int
	Zones                   []string
	AxfrEnabled             bool
	DefaultTTL              int64
	MinTTL                  int64
	CircuitBreakerThreshold int
	DomainFilter            []string
	OwnershipLabel          string
	DryRun                  bool
}

// Endpoint is the wire-compatible external-dns endpoint shape. We carry
// only the fields the sidecar can faithfully round-trip; extras like
// ProviderSpecific are accepted on the way in but otherwise ignored.
type Endpoint struct {
	DNSName    string
	Targets    []string
	RecordType string
	RecordTTL  int64
	Labels     map[string]string
}

// Changes is the inbound change-set from external-dns POST /records.
type Changes struct {
	Create    []*Endpoint
	UpdateOld []*Endpoint
	UpdateNew []*Endpoint
	Delete    []*Endpoint
}

// Orchestrator is the runtime object. Construct once at boot.
type Orchestrator struct {
	opts    Options
	client  dnsop.Client
	cache   *state.AXFRCache
	pins    *state.ZonePins
	zlocks  *state.ZoneLocks
	breaker *state.DCBreaker

	// axfrMu coalesces concurrent /records calls so we AXFR each zone at
	// most once per "fresh" round even if many goroutines call ListRecords
	// in parallel. The simplest correct implementation: take this lock for
	// the whole ListRecords body. Volume is low (operator polls every
	// CRON tick) and AXFR completes in tens of milliseconds.
	axfrMu sync.Mutex
}

// New constructs an Orchestrator. `client` is the low-level DNS protocol
// surface (real or fake). All collaborators (cache, pins, locks, breaker)
// are owned by the Orchestrator — callers don't share them.
func New(opts Options, client dnsop.Client) *Orchestrator {
	return &Orchestrator{
		opts:    opts,
		client:  client,
		cache:   state.NewAXFRCache(),
		pins:    state.NewZonePins(),
		zlocks:  state.NewZoneLocks(),
		breaker: state.NewDCBreaker(opts.CircuitBreakerThreshold),
	}
}

// Zones returns the configured zone list (copy) for the GET / handler.
func (o *Orchestrator) Zones() []string {
	out := make([]string, len(o.opts.Zones))
	copy(out, o.opts.Zones)
	return out
}

// ListRecords refreshes every configured zone via AXFR (failing over across
// available DCs) and returns Endpoints reconstructed from the ownership-TXT
// bridge: for every data record (A/AAAA/CNAME/MX/NS) at name N whose
// sibling TXT at "ddo-<type>.N" carries our owned-by= label, emit an
// Endpoint with Labels["owner"] populated.
//
// When AXFR is disabled, returns an empty slice — the operator-side
// reconciler will then treat the upstream as opaque and rely on UPDATE
// prerequisites to catch collisions.
func (o *Orchestrator) ListRecords(ctx context.Context) ([]*Endpoint, error) {
	o.axfrMu.Lock()
	defer o.axfrMu.Unlock()

	if !o.opts.AxfrEnabled {
		return []*Endpoint{}, nil
	}

	availableDCs := o.availableDCs()
	if len(availableDCs) == 0 {
		return nil, errors.New("no DCs available (all circuits open)")
	}

	dcsTried := map[string]struct{}{}
	dcsSucceeded := map[string]struct{}{}

	out := []*Endpoint{}
	ownershipValue := o.ownershipValue()

	for _, zone := range o.opts.Zones {
		recs, dc, err := o.axfrZone(ctx, zone, availableDCs, dcsTried)
		if err != nil {
			o.cache.Drop(zone)
			log.Printf("orchestrator: zone=%s AXFR failed across all DCs: %v", zone, err)
			continue
		}
		dcsSucceeded[dc] = struct{}{}
		o.pins.Set(zone, dc)
		o.cache.Put(zone, recs)

		out = append(out, o.endpointsFromRecords(recs, zone, ownershipValue)...)
	}

	// Update breaker bookkeeping: anything tried but not succeeded counts
	// as a fail-this-cycle; success clears the streak.
	for dc := range dcsTried {
		if _, ok := dcsSucceeded[dc]; ok {
			o.breaker.RecordSuccess(dc)
			continue
		}
		if d := o.breaker.RecordFailure(dc); d > 0 {
			log.Printf("orchestrator: DC %s circuit opened for %v", dc, d)
		}
	}

	return out, nil
}

func (o *Orchestrator) axfrZone(ctx context.Context, zone string, availableDCs []string, tried map[string]struct{}) ([]dnsop.Record, string, error) {
	order := o.dcOrderForZone(zone, availableDCs)
	var lastErr error
	for _, dc := range order {
		if err := ctx.Err(); err != nil {
			return nil, "", err
		}
		tried[dc] = struct{}{}
		res := o.client.AXFR(dc, o.opts.Port, zone)
		if res.OK {
			return res.Records, dc, nil
		}
		log.Printf("orchestrator: AXFR dc=%s zone=%s phase=%s message=%s", dc, zone, res.Phase, res.Message)
		lastErr = fmt.Errorf("dc=%s phase=%s: %s", dc, res.Phase, res.Message)
	}
	if lastErr == nil {
		lastErr = errors.New("no DCs available")
	}
	return nil, "", lastErr
}

// ApplyChanges fans out a webhook Changes payload to per-zone change sets,
// wraps each in ownership-TXT bookkeeping, and sends an UPDATE per zone
// (with DC failover). Returns the first error encountered if any.
func (o *Orchestrator) ApplyChanges(ctx context.Context, ch Changes) error {
	// Group everything by zone first so we can issue one UPDATE per zone.
	type zoneOps struct {
		create    []*Endpoint
		updateOld []*Endpoint
		updateNew []*Endpoint
		del       []*Endpoint
	}
	byZone := map[string]*zoneOps{}
	addCreate := func(e *Endpoint) {
		if e == nil {
			return
		}
		if !o.matchesDomainFilter(e.DNSName) {
			log.Printf("orchestrator: skip create %s — does not match RFC2136_DOMAIN_FILTER", e.DNSName)
			return
		}
		z := o.zoneFor(e.DNSName)
		if z == "" {
			log.Printf("orchestrator: skip create %s — no matching zone", e.DNSName)
			return
		}
		bucket(byZone, z).create = append(bucket(byZone, z).create, e)
	}
	addDelete := func(e *Endpoint) {
		if e == nil {
			return
		}
		if !o.matchesDomainFilter(e.DNSName) {
			log.Printf("orchestrator: skip delete %s — does not match RFC2136_DOMAIN_FILTER", e.DNSName)
			return
		}
		z := o.zoneFor(e.DNSName)
		if z == "" {
			log.Printf("orchestrator: skip delete %s — no matching zone", e.DNSName)
			return
		}
		bucket(byZone, z).del = append(bucket(byZone, z).del, e)
	}
	for _, e := range ch.Create {
		addCreate(e)
	}
	for _, e := range ch.Delete {
		addDelete(e)
	}
	// Updates are paired UpdateOld/UpdateNew, same index — external-dns
	// guarantees same length and ordering.
	n := len(ch.UpdateOld)
	if n > len(ch.UpdateNew) {
		n = len(ch.UpdateNew)
	}
	for i := 0; i < n; i++ {
		oldE, newE := ch.UpdateOld[i], ch.UpdateNew[i]
		if oldE == nil || newE == nil {
			continue
		}
		if !o.matchesDomainFilter(newE.DNSName) {
			log.Printf("orchestrator: skip update %s — does not match RFC2136_DOMAIN_FILTER", newE.DNSName)
			continue
		}
		z := o.zoneFor(newE.DNSName)
		if z == "" {
			log.Printf("orchestrator: skip update %s — no matching zone", newE.DNSName)
			continue
		}
		bucket(byZone, z).updateOld = append(bucket(byZone, z).updateOld, oldE)
		bucket(byZone, z).updateNew = append(bucket(byZone, z).updateNew, newE)
	}

	var firstErr error
	for zone, ops := range byZone {
		zoneCs, err := o.buildZoneChangeSet(zone, ops.create, ops.updateOld, ops.updateNew, ops.del)
		if err != nil {
			log.Printf("orchestrator: zone=%s build change-set: %v", zone, err)
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		if len(zoneCs.changes) == 0 {
			continue
		}
		if o.opts.DryRun {
			log.Printf("[dry-run] orchestrator: zone=%s prereqs=%d changes=%d", zone, len(zoneCs.prereqs), len(zoneCs.changes))
			continue
		}
		if err := o.applyZone(ctx, zone, zoneCs); err != nil {
			log.Printf("orchestrator: zone=%s apply: %v", zone, err)
			if firstErr == nil {
				firstErr = err
			}
		}
	}
	return firstErr
}

type zoneChangeSet struct {
	prereqs []dnsop.Prereq
	changes []dnsop.Change
}

// buildZoneChangeSet assembles the prereqs+changes for one zone. The
// ownership-TXT bridge is woven in here:
//
//   - Create: NXRRSET on data name+type, NXRRSET on ownership TXT name+TXT,
//     add data record, add ownership TXT. If the ownership TXT already
//     exists as an orphan (cached from a previous incomplete delete), skip
//     the second prereq and the TXT add.
//   - Update: YXRRSET on ownership TXT (we won't touch a record we don't
//     own), delete old data, add new data. TXT stays untouched.
//   - Delete: YXRRSET on ownership TXT, delete data, delete ownership TXT.
func (o *Orchestrator) buildZoneChangeSet(zone string, creates, updOld, updNew, dels []*Endpoint) (zoneChangeSet, error) {
	cached, _ := o.cache.Get(zone)
	cachedByName := indexByName(cached)
	orphanOwnership := o.orphanOwnership(cached)
	ownershipValue := o.ownershipValue()

	var cs zoneChangeSet

	for _, e := range creates {
		for _, recs := range o.endpointToRecords(e) {
			if o.opts.AxfrEnabled {
				if reason := o.collisionReason(cachedByName, recs, ownershipValue); reason != "" {
					log.Printf("orchestrator: skip create %s/%s — collision: %s", recs.Name, recs.Type, reason)
					continue
				}
			}
			ownershipName := ownershipNameFor(recs.Type, recs.Name)
			isOrphan := orphanOwnership[ownershipName]
			cs.prereqs = append(cs.prereqs, dnsop.Prereq{Kind: "NXRRSET", Name: recs.Name, Type: recs.Type})
			if !isOrphan {
				cs.prereqs = append(cs.prereqs, dnsop.Prereq{Kind: "NXRRSET", Name: ownershipName, Type: "TXT"})
			}
			cs.changes = append(cs.changes, dnsop.Change{Op: "add", Record: recs})
			if !isOrphan {
				cs.changes = append(cs.changes, dnsop.Change{
					Op: "add",
					Record: dnsop.Record{
						Name:  ownershipName,
						Type:  "TXT",
						TTL:   recs.TTL,
						Value: ownershipValue,
					},
				})
			}
		}
	}

	for i := range updOld {
		oldRecs := o.endpointToRecords(updOld[i])
		newRecs := o.endpointToRecords(updNew[i])
		// Pair by type: external-dns updates always preserve type. We
		// generate a delete-old/add-new per record.
		for _, oldR := range oldRecs {
			ownershipName := ownershipNameFor(oldR.Type, oldR.Name)
			cs.prereqs = append(cs.prereqs, dnsop.Prereq{
				Kind: "YXRRSET", Name: ownershipName, Type: "TXT", Value: ownershipValue,
			})
			cs.changes = append(cs.changes, dnsop.Change{Op: "delete", Record: oldR})
		}
		for _, newR := range newRecs {
			cs.changes = append(cs.changes, dnsop.Change{Op: "add", Record: newR})
		}
	}

	for _, e := range dels {
		for _, r := range o.endpointToRecords(e) {
			ownershipName := ownershipNameFor(r.Type, r.Name)
			cs.prereqs = append(cs.prereqs, dnsop.Prereq{
				Kind: "YXRRSET", Name: ownershipName, Type: "TXT", Value: ownershipValue,
			})
			cs.changes = append(cs.changes, dnsop.Change{Op: "delete", Record: r})
			cs.changes = append(cs.changes, dnsop.Change{
				Op: "delete",
				Record: dnsop.Record{
					Name:  ownershipName,
					Type:  "TXT",
					TTL:   0,
					Value: ownershipValue,
				},
			})
		}
	}

	return cs, nil
}

// applyZone takes the per-zone lock and walks the DC failover order. The
// failover policy mirrors the operator: try the pinned DC first, then the
// remaining available DCs in the configured order. Stop on the first
// non-retryable, non-failover-eligible rcode.
func (o *Orchestrator) applyZone(ctx context.Context, zone string, cs zoneChangeSet) error {
	zoneMu := o.zlocks.For(zone)
	zoneMu.Lock()
	defer zoneMu.Unlock()

	availableDCs := o.availableDCs()
	if len(availableDCs) == 0 {
		return errors.New("no DCs available (all circuits open)")
	}
	order := o.dcOrderForZone(zone, availableDCs)

	var lastFailure string
	for _, dc := range order {
		if err := ctx.Err(); err != nil {
			return err
		}
		res := o.client.Update(dc, o.opts.Port, zone, cs.prereqs, cs.changes)
		if res.OK {
			o.pins.Set(zone, dc)
			o.breaker.RecordSuccess(dc)
			return nil
		}
		lastFailure = fmt.Sprintf("dc=%s rcode=%s phase=%s msg=%s", dc, res.Rcode, res.Phase, res.Message)
		log.Printf("orchestrator: UPDATE %s", lastFailure)
		if !isFailoverEligible(res) {
			return fmt.Errorf("UPDATE failed (non-retryable): %s", lastFailure)
		}
		if d := o.breaker.RecordFailure(dc); d > 0 {
			log.Printf("orchestrator: DC %s circuit opened for %v", dc, d)
		}
	}
	return fmt.Errorf("UPDATE exhausted %d DC(s); last: %s", len(order), lastFailure)
}

var failoverRcodes = map[string]struct{}{
	"SERVFAIL": {},
	"REFUSED":  {},
	"NOTAUTH":  {},
}

func isFailoverEligible(res dnsop.ApplyResult) bool {
	if res.Retryable {
		return true
	}
	_, ok := failoverRcodes[res.Rcode]
	return ok
}

// --- helpers --------------------------------------------------------------

func (o *Orchestrator) availableDCs() []string {
	out := make([]string, 0, len(o.opts.Hosts))
	for _, dc := range o.opts.Hosts {
		if o.breaker.IsAvailable(dc) {
			out = append(out, dc)
		}
	}
	return out
}

// dcOrderForZone returns the DC walk order for a zone: the sticky pin (if
// it's still available) first, then the remaining available DCs in the
// configured order with dups removed.
func (o *Orchestrator) dcOrderForZone(zone string, available []string) []string {
	var order []string
	if pinned, ok := o.pins.Get(zone); ok {
		for _, dc := range available {
			if dc == pinned {
				order = append(order, dc)
				break
			}
		}
	}
	for _, dc := range available {
		if len(order) == 1 && dc == order[0] {
			continue
		}
		order = append(order, dc)
	}
	return order
}

func (o *Orchestrator) matchesDomainFilter(fqdn string) bool {
	if len(o.opts.DomainFilter) == 0 {
		return true
	}
	name := normalizeName(fqdn)
	for _, suffix := range o.opts.DomainFilter {
		if name == suffix || strings.HasSuffix(name, "."+suffix) {
			return true
		}
	}
	return false
}

// zoneFor returns the longest-matching configured zone for an fqdn, or "".
func (o *Orchestrator) zoneFor(fqdn string) string {
	name := normalizeName(fqdn)
	matches := []string{}
	for _, z := range o.opts.Zones {
		if name == z || strings.HasSuffix(name, "."+z) {
			matches = append(matches, z)
		}
	}
	if len(matches) == 0 {
		return ""
	}
	sort.Slice(matches, func(i, j int) bool { return len(matches[i]) > len(matches[j]) })
	return matches[0]
}

func normalizeName(fqdn string) string {
	return strings.ToLower(strings.TrimSuffix(fqdn, "."))
}

func (o *Orchestrator) ownershipValue() string {
	return `"owned-by=` + o.opts.OwnershipLabel + `"`
}

func ownershipNameFor(recType, name string) string {
	return "ddo-" + strings.ToLower(recType) + "." + normalizeName(name)
}

func indexByName(recs []dnsop.Record) map[string][]dnsop.Record {
	out := map[string][]dnsop.Record{}
	for _, r := range recs {
		k := normalizeName(r.Name)
		out[k] = append(out[k], r)
	}
	return out
}

// orphanOwnership returns the set of ownership-TXT names we own that have
// no matching sibling data record (e.g. a previous delete crashed between
// the data-record delete and the TXT delete). Callers tolerate these by
// skipping the NXRRSET prereq on the TXT for subsequent creates.
func (o *Orchestrator) orphanOwnership(recs []dnsop.Record) map[string]bool {
	ownershipValue := o.ownershipValue()
	byName := indexByName(recs)
	orphans := map[string]bool{}
	for _, r := range recs {
		if r.Type != "TXT" || r.Value != ownershipValue {
			continue
		}
		nm := normalizeName(r.Name)
		// "ddo-<type>.<datast-name>" — split the leftmost label.
		if !strings.HasPrefix(nm, "ddo-") {
			continue
		}
		dot := strings.IndexByte(nm, '.')
		if dot < 0 {
			continue
		}
		typeLc := nm[len("ddo-"):dot]
		dataName := nm[dot+1:]
		dataType := strings.ToUpper(typeLc)
		siblings := byName[dataName]
		hasSibling := false
		for _, s := range siblings {
			if s.Type == dataType {
				hasSibling = true
				break
			}
		}
		if !hasSibling {
			orphans[nm] = true
			log.Printf("orchestrator: orphan ownership TXT %s — sibling %s missing", nm, dataName)
		}
	}
	return orphans
}

// collisionReason returns a non-empty string when proposing `r` at its
// name+type would violate RFC1034 §3.6.2 (CNAME mutual exclusion) or
// would overwrite an existing record we don't own.
func (o *Orchestrator) collisionReason(cachedByName map[string][]dnsop.Record, r dnsop.Record, ownershipValue string) string {
	name := normalizeName(r.Name)
	sameName := cachedByName[name]
	hasCname := false
	hasNonCname := false
	var existingSameType *dnsop.Record
	for i := range sameName {
		s := sameName[i]
		if s.Type == "CNAME" {
			hasCname = true
		} else if s.Type != "TXT" {
			hasNonCname = true
		}
		if s.Type == r.Type {
			existingSameType = &sameName[i]
		}
	}
	if r.Type == "CNAME" && hasNonCname {
		return "RFC1034 §3.6.2: CNAME cannot coexist with other types"
	}
	if r.Type != "CNAME" && hasCname {
		return "RFC1034 §3.6.2: CNAME at name forbids other types"
	}
	if existingSameType != nil {
		// Already exists at same type. Allowed only if we own it.
		ownershipName := ownershipNameFor(r.Type, r.Name)
		owned := false
		for _, s := range cachedByName[ownershipName] {
			if s.Type == "TXT" && s.Value == ownershipValue {
				owned = true
				break
			}
		}
		if !owned {
			return fmt.Sprintf("existing unowned %s record at %s", r.Type, r.Name)
		}
	}
	return ""
}

// --- endpoint <-> record translation --------------------------------------

// endpointToRecords expands a single multi-target Endpoint into one or more
// dnsop.Record values, one per target. A/AAAA: one Record per IP. CNAME/NS:
// one Record per hostname. MX: one Record per "<prio> <host>" string. TTL
// is clamped to [MinTTL, +inf] and falls back to DefaultTTL when zero.
func (o *Orchestrator) endpointToRecords(e *Endpoint) []dnsop.Record {
	if e == nil || len(e.Targets) == 0 {
		return nil
	}
	rtype := strings.ToUpper(e.RecordType)
	switch rtype {
	case "A", "AAAA", "CNAME", "NS", "MX":
	default:
		log.Printf("orchestrator: unsupported recordType %q — skipping endpoint %s", rtype, e.DNSName)
		return nil
	}

	ttl := e.RecordTTL
	if ttl <= 0 {
		ttl = o.opts.DefaultTTL
	}
	if ttl < o.opts.MinTTL {
		ttl = o.opts.MinTTL
	}

	name := normalizeName(e.DNSName)
	out := make([]dnsop.Record, 0, len(e.Targets))
	for _, t := range e.Targets {
		v := canonicalRdata(rtype, t)
		if v == "" {
			continue
		}
		out = append(out, dnsop.Record{Name: name, Type: rtype, TTL: int(ttl), Value: v})
	}
	return out
}

// canonicalRdata coerces an external-dns target string into the zone-file
// rdata our dnsop layer wants ("10.1.2.3", "host.example.com.",
// "10 mx.example.com."). Returns "" on unrecoverable input.
func canonicalRdata(rtype, target string) string {
	t := strings.TrimSpace(target)
	if t == "" {
		return ""
	}
	switch rtype {
	case "A", "AAAA":
		return strings.ToLower(t)
	case "CNAME", "NS":
		t = strings.ToLower(t)
		if !strings.HasSuffix(t, ".") {
			t += "."
		}
		return t
	case "MX":
		// Accept "10 mx.example.com" or "10 mx.example.com." — emit the
		// dotted form. Anything that doesn't split into a numeric priority
		// + hostname is rejected.
		parts := strings.Fields(t)
		if len(parts) != 2 {
			return ""
		}
		host := strings.ToLower(parts[1])
		if !strings.HasSuffix(host, ".") {
			host += "."
		}
		return parts[0] + " " + host
	}
	return ""
}

// endpointsFromRecords reconstructs Endpoints from a flat record list by
// grouping by (name, type) and keeping only those with an ownership-TXT
// sibling carrying our owned-by= label. Each returned Endpoint has
// Labels["owner"] populated.
func (o *Orchestrator) endpointsFromRecords(recs []dnsop.Record, zone, ownershipValue string) []*Endpoint {
	// Build (name -> set-of-owned-types) index from ownership TXTs we wrote.
	ownedTypes := map[string]map[string]bool{}
	for _, r := range recs {
		if r.Type != "TXT" || r.Value != ownershipValue {
			continue
		}
		nm := normalizeName(r.Name)
		if !strings.HasPrefix(nm, "ddo-") {
			continue
		}
		dot := strings.IndexByte(nm, '.')
		if dot < 0 {
			continue
		}
		typeLc := nm[len("ddo-"):dot]
		dataName := nm[dot+1:]
		set, ok := ownedTypes[dataName]
		if !ok {
			set = map[string]bool{}
			ownedTypes[dataName] = set
		}
		set[strings.ToUpper(typeLc)] = true
	}

	// Group data records by (name, type) → []targets. Skip non-managed ones.
	type key struct{ name, rtype string }
	bucketRecs := map[key]*Endpoint{}
	var order []key
	for _, r := range recs {
		if r.Type == "TXT" {
			continue
		}
		if !o.matchesDomainFilter(r.Name) {
			continue
		}
		name := normalizeName(r.Name)
		types, ok := ownedTypes[name]
		if !ok || !types[r.Type] {
			continue
		}
		k := key{name, r.Type}
		ep, exists := bucketRecs[k]
		if !exists {
			ep = &Endpoint{
				DNSName:    name,
				RecordType: r.Type,
				RecordTTL:  int64(r.TTL),
				Labels: map[string]string{
					"owner":    o.opts.OwnershipLabel,
					"resource": "rfc2136/" + zone,
				},
			}
			bucketRecs[k] = ep
			order = append(order, k)
		}
		ep.Targets = append(ep.Targets, r.Value)
	}

	out := make([]*Endpoint, 0, len(order))
	for _, k := range order {
		out = append(out, bucketRecs[k])
	}
	return out
}

func bucket[T any](m map[string]*T, k string) *T {
	v, ok := m[k]
	if !ok {
		v = new(T)
		m[k] = v
	}
	return v
}
