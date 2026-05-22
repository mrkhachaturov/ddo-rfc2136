package api

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/mrkhachaturov/ddo-rfc2136/internal/dnsop"
	"github.com/mrkhachaturov/ddo-rfc2136/internal/state"
)

type fakeClient struct {
	axfrResult   dnsop.RecordsResult
	updateResult dnsop.ApplyResult
	lastAxfr     dnsop.RecordsResult
	lastUpdate   dnsop.ApplyResult
	calls        []string
}

func (f *fakeClient) AXFR(host string, port int, zone string) dnsop.RecordsResult {
	f.calls = append(f.calls, "AXFR:"+host+":"+zone)
	return f.axfrResult
}

func (f *fakeClient) Update(host string, port int, zone string, prereqs []dnsop.Prereq, changes []dnsop.Change) dnsop.ApplyResult {
	f.calls = append(f.calls, "UPDATE:"+host+":"+zone)
	return f.updateResult
}

func TestRecordsHandler_OK(t *testing.T) {
	fc := &fakeClient{axfrResult: dnsop.RecordsResult{OK: true, Records: []dnsop.Record{{Name: "a.example.com", Type: "A", TTL: 300, Value: "10.1.2.3"}}}}
	h := NewHandlers(fc, true)
	body, _ := json.Marshal(RecordsRequest{Host: "dc01.corp.example.com", Port: 53, Zone: "example.com"})
	rr := httptest.NewRecorder()
	h.Records(rr, httptest.NewRequest(http.MethodPost, "/v1/records", bytes.NewReader(body)))
	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
	var resp dnsop.RecordsResult
	_ = json.NewDecoder(rr.Body).Decode(&resp)
	if !resp.OK || len(resp.Records) != 1 {
		t.Fatalf("bad response: %+v", resp)
	}
}

func TestApplyHandler_DryRunSkipsClient(t *testing.T) {
	fc := &fakeClient{updateResult: dnsop.ApplyResult{OK: true}}
	h := NewHandlers(fc, true /* dryRun */)
	body, _ := json.Marshal(ApplyRequest{
		Host: "dc01.corp.example.com", Port: 53, Zone: "example.com",
		Changes: []dnsop.Change{{Op: "add", Record: dnsop.Record{Name: "x.example.com", Type: "A", TTL: 300, Value: "10.0.0.1"}}},
	})
	rr := httptest.NewRecorder()
	h.Apply(rr, httptest.NewRequest(http.MethodPost, "/v1/apply", bytes.NewReader(body)))
	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d", rr.Code)
	}
	if len(fc.calls) != 0 {
		t.Fatalf("dry-run must not call client, got %v", fc.calls)
	}
}

func TestApplyHandler_PassesPrereqsAndChanges(t *testing.T) {
	fc := &fakeClient{updateResult: dnsop.ApplyResult{OK: true}}
	h := NewHandlers(fc, false)
	req := ApplyRequest{
		Host: "dc01.corp.example.com", Port: 53, Zone: "example.com",
		Prerequisites: []dnsop.Prereq{{Kind: "NXRRSET", Name: "x.example.com", Type: "A"}},
		Changes:       []dnsop.Change{{Op: "add", Record: dnsop.Record{Name: "x.example.com", Type: "A", TTL: 300, Value: "10.0.0.1"}}},
	}
	body, _ := json.Marshal(req)
	rr := httptest.NewRecorder()
	h.Apply(rr, httptest.NewRequest(http.MethodPost, "/v1/apply", bytes.NewReader(body)))
	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rr.Code, readAll(rr.Body))
	}
	if len(fc.calls) != 1 || fc.calls[0] != "UPDATE:dc01.corp.example.com:example.com" {
		t.Fatalf("unexpected calls: %v", fc.calls)
	}
}

func readAll(b interface{ Read(p []byte) (int, error) }) string {
	out, _ := io.ReadAll(b)
	return string(out)
}

func TestHealthz_NoStateReportsReadyForBackCompat(t *testing.T) {
	h := NewHandlers(&fakeClient{}, false)
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
	h := NewHandlersWithState(&fakeClient{}, false, st)
	rr := httptest.NewRecorder()
	h.Healthz(rr, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("status=%d want 503 for unknown state", rr.Code)
	}
	var resp HealthResponse
	_ = json.NewDecoder(rr.Body).Decode(&resp)
	if resp.OK || resp.Kerberos != "unknown" {
		t.Fatalf("bad response: %+v", resp)
	}
}

func TestHealthz_ReadyReturns200(t *testing.T) {
	st := state.NewKerberos()
	st.MarkReady(time.Unix(1700000000, 0))
	h := NewHandlersWithState(&fakeClient{}, false, st)
	rr := httptest.NewRecorder()
	h.Healthz(rr, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d want 200", rr.Code)
	}
	var resp HealthResponse
	_ = json.NewDecoder(rr.Body).Decode(&resp)
	if !resp.OK || resp.Kerberos != "ready" || resp.Detail != "" {
		t.Fatalf("bad response: %+v", resp)
	}
}

func TestHealthz_ExpiredReturns503WithDetail(t *testing.T) {
	st := state.NewKerberos()
	st.MarkReady(time.Unix(1700000000, 0))
	st.MarkExpired("kinit: KDC unreachable")
	h := NewHandlersWithState(&fakeClient{}, false, st)
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
