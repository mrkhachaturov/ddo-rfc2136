package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/mrkhachaturov/ddo-rfc2136/internal/orchestrator"
	"github.com/mrkhachaturov/ddo-rfc2136/internal/state"
)

// fakeProvider is the test seam for the orchestrator surface.
type fakeProvider struct {
	zones       []string
	records     []*orchestrator.Endpoint
	listErr     error
	applyErr    error
	lastApplied orchestrator.Changes
	applyCalls  int
}

func (f *fakeProvider) Zones() []string { return f.zones }

func (f *fakeProvider) ListRecords(_ context.Context) ([]*orchestrator.Endpoint, error) {
	return f.records, f.listErr
}

func (f *fakeProvider) ApplyChanges(_ context.Context, ch orchestrator.Changes) error {
	f.applyCalls++
	f.lastApplied = ch
	return f.applyErr
}

func TestNegotiate_ReturnsFiltersFromProvider(t *testing.T) {
	fp := &fakeProvider{zones: []string{"corp.example.com", "other.example.com"}}
	h := NewHandlers(fp, nil)
	rr := httptest.NewRecorder()
	h.Negotiate(rr, httptest.NewRequest(http.MethodGet, "/", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d", rr.Code)
	}
	if ct := rr.Header().Get("Content-Type"); ct != MediaTypeFormatAndVersion {
		t.Fatalf("content-type: %q", ct)
	}
	// Decode against upstream's wire field (`include`) to catch regressions
	// where a future edit renames the Go field but forgets the json tag.
	var got struct {
		Include []string `json:"include"`
		Filters []string `json:"filters"`
	}
	if err := json.NewDecoder(rr.Body).Decode(&got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got.Filters != nil {
		t.Fatalf("legacy `filters` key resurfaced: upstream treats this as 'no filter', breaking domain-scoped routing")
	}
	if len(got.Include) != 2 || got.Include[0] != "corp.example.com" {
		t.Fatalf("include: %+v", got)
	}
}

func TestRecords_ReturnsWireEndpoints(t *testing.T) {
	fp := &fakeProvider{records: []*orchestrator.Endpoint{
		{
			DNSName:    "app.corp.example.com",
			RecordType: "A",
			RecordTTL:  300,
			Targets:    []string{"10.1.2.3"},
			Labels:     map[string]string{"owner": "docker-dns-operator:1"},
		},
	}}
	h := NewHandlers(fp, nil)
	rr := httptest.NewRecorder()
	h.Records(rr, httptest.NewRequest(http.MethodGet, "/records", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
	var got []*Endpoint
	if err := json.NewDecoder(rr.Body).Decode(&got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(got) != 1 || got[0].DNSName != "app.corp.example.com" || got[0].Labels["owner"] != "docker-dns-operator:1" {
		t.Fatalf("bad records: %+v", got)
	}
}

func TestRecords_PropagatesProviderError(t *testing.T) {
	fp := &fakeProvider{listErr: errors.New("axfr unreachable")}
	h := NewHandlers(fp, nil)
	rr := httptest.NewRecorder()
	h.Records(rr, httptest.NewRequest(http.MethodGet, "/records", nil))
	if rr.Code != http.StatusInternalServerError {
		t.Fatalf("status=%d", rr.Code)
	}
}

func TestApplyChanges_HappyPathReturns204(t *testing.T) {
	fp := &fakeProvider{}
	h := NewHandlers(fp, nil)
	body, _ := json.Marshal(Changes{
		Create: []*Endpoint{{DNSName: "app.corp.example.com", RecordType: "A", RecordTTL: 300, Targets: []string{"10.0.0.1"}}},
	})
	rr := httptest.NewRecorder()
	h.ApplyChanges(rr, httptest.NewRequest(http.MethodPost, "/records", bytes.NewReader(body)))
	if rr.Code != http.StatusNoContent {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
	if fp.applyCalls != 1 {
		t.Fatalf("expected exactly 1 apply call, got %d", fp.applyCalls)
	}
	if len(fp.lastApplied.Create) != 1 || fp.lastApplied.Create[0].DNSName != "app.corp.example.com" {
		t.Fatalf("orchestrator did not see the create: %+v", fp.lastApplied)
	}
}

func TestApplyChanges_BadJsonReturns400(t *testing.T) {
	fp := &fakeProvider{}
	h := NewHandlers(fp, nil)
	rr := httptest.NewRecorder()
	h.ApplyChanges(rr, httptest.NewRequest(http.MethodPost, "/records", strings.NewReader("{not json")))
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status=%d", rr.Code)
	}
	if fp.applyCalls != 0 {
		t.Fatalf("orchestrator must not be called on bad JSON")
	}
}

func TestApplyChanges_ProviderErrorReturns500(t *testing.T) {
	fp := &fakeProvider{applyErr: errors.New("update failed")}
	h := NewHandlers(fp, nil)
	body, _ := json.Marshal(Changes{Create: []*Endpoint{{DNSName: "x.corp.example.com", RecordType: "A", Targets: []string{"1.1.1.1"}}}})
	rr := httptest.NewRecorder()
	h.ApplyChanges(rr, httptest.NewRequest(http.MethodPost, "/records", bytes.NewReader(body)))
	if rr.Code != http.StatusInternalServerError {
		t.Fatalf("status=%d", rr.Code)
	}
}

func TestAdjustEndpoints_EchoesInput(t *testing.T) {
	fp := &fakeProvider{}
	h := NewHandlers(fp, nil)
	in := []*Endpoint{{DNSName: "x.corp.example.com", RecordType: "A", Targets: []string{"1.1.1.1"}}}
	body, _ := json.Marshal(in)
	rr := httptest.NewRecorder()
	h.AdjustEndpoints(rr, httptest.NewRequest(http.MethodPost, "/adjustendpoints", bytes.NewReader(body)))
	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d", rr.Code)
	}
	var got []*Endpoint
	_ = json.NewDecoder(rr.Body).Decode(&got)
	if len(got) != 1 || got[0].DNSName != "x.corp.example.com" {
		t.Fatalf("did not echo input: %+v", got)
	}
}

func TestHealthz_NoStateReportsReadyForBackCompat(t *testing.T) {
	h := NewHandlers(&fakeProvider{}, nil)
	rr := httptest.NewRecorder()
	h.Healthz(rr, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d", rr.Code)
	}
	var resp HealthResponse
	_ = json.NewDecoder(rr.Body).Decode(&resp)
	if !resp.OK || resp.Kerberos != "ready" {
		t.Fatalf("bad response: %+v", resp)
	}
}

func TestHealthz_UnknownBeforeFirstRefresh(t *testing.T) {
	st := state.NewKerberos()
	h := NewHandlers(&fakeProvider{}, st)
	rr := httptest.NewRecorder()
	h.Healthz(rr, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("status=%d want 503 for unknown state", rr.Code)
	}
}

func TestHealthz_ReadyReturns200(t *testing.T) {
	st := state.NewKerberos()
	st.MarkReady(time.Unix(1700000000, 0))
	h := NewHandlers(&fakeProvider{}, st)
	rr := httptest.NewRecorder()
	h.Healthz(rr, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d", rr.Code)
	}
}

func TestHealthz_ExpiredReturns503WithDetail(t *testing.T) {
	st := state.NewKerberos()
	st.MarkReady(time.Unix(1700000000, 0))
	st.MarkExpired("kinit: KDC unreachable")
	h := NewHandlers(&fakeProvider{}, st)
	rr := httptest.NewRecorder()
	h.Healthz(rr, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("status=%d want 503", rr.Code)
	}
	var resp HealthResponse
	_ = json.NewDecoder(rr.Body).Decode(&resp)
	if resp.OK || resp.Kerberos != "expired" || resp.Detail != "kinit: KDC unreachable" {
		t.Fatalf("bad response: %+v", resp)
	}
}
