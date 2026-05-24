package api

import (
	"context"
	"encoding/json"
	"net/http"

	"github.com/mrkhachaturov/ddo-rfc2136/internal/orchestrator"
	"github.com/mrkhachaturov/ddo-rfc2136/internal/state"
)

// Provider is the orchestrator-facing surface the handler needs. Defined
// as an interface so tests can fake it without booting the real DNS stack.
type Provider interface {
	Zones() []string
	ListRecords(ctx context.Context) ([]*orchestrator.Endpoint, error)
	ApplyChanges(ctx context.Context, ch orchestrator.Changes) error
}

// Handlers owns the four external-dns v1 endpoints plus /healthz.
type Handlers struct {
	provider Provider
	// krb may be nil in tests; when nil the /healthz handler reports
	// "ready" unconditionally for back-compat with the original wire.
	krb *state.Kerberos
}

// NewHandlers wires the orchestrator and Kerberos state into the HTTP
// surface. Both arguments are optional (krb may be nil in tests).
func NewHandlers(p Provider, krb *state.Kerberos) *Handlers {
	return &Handlers{provider: p, krb: krb}
}

// Negotiate handles GET / — external-dns calls this first to discover the
// domain filter we accept records for. The body is `{"filters":["zone1"]}`.
func (h *Handlers) Negotiate(w http.ResponseWriter, _ *http.Request) {
	writeWebhookJSON(w, http.StatusOK, Filters{Filters: h.provider.Zones()})
}

// Records handles GET /records — returns every Endpoint the sidecar manages,
// reconstructed from the AXFR cache via the ownership-TXT bridge.
func (h *Handlers) Records(w http.ResponseWriter, r *http.Request) {
	eps, err := h.provider.ListRecords(r.Context())
	if err != nil {
		writeWebhookJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	out := make([]*Endpoint, 0, len(eps))
	for _, e := range eps {
		out = append(out, toWireEndpoint(e))
	}
	writeWebhookJSON(w, http.StatusOK, out)
}

// ApplyChanges handles POST /records — decodes Changes and forwards to the
// orchestrator. Success is 204 No Content (external-dns expects the body
// to be empty on success).
func (h *Handlers) ApplyChanges(w http.ResponseWriter, r *http.Request) {
	var wire Changes
	if err := json.NewDecoder(r.Body).Decode(&wire); err != nil {
		writeWebhookJSON(w, http.StatusBadRequest, map[string]string{"error": "bad json: " + err.Error()})
		return
	}
	if err := h.provider.ApplyChanges(r.Context(), toDomainChanges(&wire)); err != nil {
		writeWebhookJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// AdjustEndpoints handles POST /adjustendpoints — external-dns sometimes
// calls this between planning and applying to let the provider normalise
// targets/TTLs. Our normalisation lives inside ApplyChanges, so we echo
// the input unchanged. Implementing this prevents external-dns from
// erroring with a 404 when it expects a provider that supports it.
func (h *Handlers) AdjustEndpoints(w http.ResponseWriter, r *http.Request) {
	var in []*Endpoint
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeWebhookJSON(w, http.StatusBadRequest, map[string]string{"error": "bad json: " + err.Error()})
		return
	}
	writeWebhookJSON(w, http.StatusOK, in)
}

// Healthz reports the current Kerberos refresh state. Status codes:
//   - 200 with ok=true when the most recent kinit succeeded ("ready").
//   - 503 with ok=false when the most recent kinit failed ("expired") or no
//     refresh has run yet ("unknown"). The sidecar keeps serving so a probe
//     can drain traffic without killing the container — recovery on the next
//     refresh tick will flip the response back to 200.
func (h *Handlers) Healthz(w http.ResponseWriter, _ *http.Request) {
	if h.krb == nil {
		writeWebhookJSON(w, http.StatusOK, HealthResponse{OK: true, Kerberos: "ready"})
		return
	}
	status, detail, _ := h.krb.Snapshot()
	ok := status == state.StatusReady
	code := http.StatusOK
	if !ok {
		code = http.StatusServiceUnavailable
	}
	writeWebhookJSON(w, code, HealthResponse{OK: ok, Kerberos: string(status), Detail: detail})
}

// --- helpers --------------------------------------------------------------

func writeWebhookJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", MediaTypeFormatAndVersion)
	w.Header().Set("Vary", "Content-Type")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func toDomainChanges(c *Changes) orchestrator.Changes {
	return orchestrator.Changes{
		Create:    toDomainEndpoints(c.Create),
		UpdateOld: toDomainEndpoints(c.UpdateOld),
		UpdateNew: toDomainEndpoints(c.UpdateNew),
		Delete:    toDomainEndpoints(c.Delete),
	}
}

func toDomainEndpoints(in []*Endpoint) []*orchestrator.Endpoint {
	if len(in) == 0 {
		return nil
	}
	out := make([]*orchestrator.Endpoint, 0, len(in))
	for _, e := range in {
		if e == nil {
			out = append(out, nil)
			continue
		}
		out = append(out, &orchestrator.Endpoint{
			DNSName:    e.DNSName,
			Targets:    append([]string(nil), e.Targets...),
			RecordType: e.RecordType,
			RecordTTL:  e.RecordTTL,
			Labels:     copyLabels(e.Labels),
		})
	}
	return out
}

func toWireEndpoint(e *orchestrator.Endpoint) *Endpoint {
	if e == nil {
		return nil
	}
	return &Endpoint{
		DNSName:    e.DNSName,
		Targets:    append([]string(nil), e.Targets...),
		RecordType: e.RecordType,
		RecordTTL:  e.RecordTTL,
		Labels:     copyLabels(e.Labels),
	}
}

func copyLabels(in map[string]string) map[string]string {
	if in == nil {
		return nil
	}
	out := make(map[string]string, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}
