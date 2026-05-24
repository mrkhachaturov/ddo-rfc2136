package state

import (
	"sync"

	"github.com/mrkhachaturov/ddo-rfc2136/internal/dnsop"
)

// AXFRCache stores the last-successful AXFR result per zone, keyed by
// canonical zone name (lower-case, no trailing dot). Reads return a copy of
// the slice header so callers can iterate safely without holding the lock.
type AXFRCache struct {
	mu   sync.RWMutex
	data map[string][]dnsop.Record
}

func NewAXFRCache() *AXFRCache { return &AXFRCache{data: map[string][]dnsop.Record{}} }

// Put stores or replaces the cached record set for a zone.
func (c *AXFRCache) Put(zone string, recs []dnsop.Record) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.data[zone] = recs
}

// Get returns (records, true) when the zone has a cached entry, otherwise
// (nil, false). The returned slice MUST NOT be mutated by the caller.
func (c *AXFRCache) Get(zone string) ([]dnsop.Record, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	r, ok := c.data[zone]
	return r, ok
}

// Drop removes a zone entry. Used when an AXFR fails so stale data isn't
// served from /records.
func (c *AXFRCache) Drop(zone string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.data, zone)
}

// ZonePins holds the "last successful DC" sticky pin per zone. Both AXFR
// and UPDATE consult the pin; a successful op against a different DC
// overwrites the pin.
type ZonePins struct {
	mu   sync.RWMutex
	data map[string]string
}

func NewZonePins() *ZonePins { return &ZonePins{data: map[string]string{}} }

func (p *ZonePins) Get(zone string) (string, bool) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	dc, ok := p.data[zone]
	return dc, ok
}

func (p *ZonePins) Set(zone, dc string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.data[zone] = dc
}

// ZoneLocks gives one mutex per zone, lazily created. Callers serialise all
// UPDATE traffic (and any AXFR that needs an exclusive view) for a given
// zone by Lock-then-Unlock around their work. This prevents racing UPDATEs
// from stepping on each other's prerequisites.
type ZoneLocks struct {
	mu    sync.Mutex
	locks map[string]*sync.Mutex
}

func NewZoneLocks() *ZoneLocks { return &ZoneLocks{locks: map[string]*sync.Mutex{}} }

func (z *ZoneLocks) For(zone string) *sync.Mutex {
	z.mu.Lock()
	defer z.mu.Unlock()
	m, ok := z.locks[zone]
	if !ok {
		m = &sync.Mutex{}
		z.locks[zone] = m
	}
	return m
}
