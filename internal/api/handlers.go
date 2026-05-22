package api

import (
	"encoding/json"
	"log"
	"net/http"

	"github.com/mrkhachaturov/docker-dns-operator/transport-rfc2136/internal/dnsop"
	"github.com/mrkhachaturov/docker-dns-operator/transport-rfc2136/internal/state"
)

type Handlers struct {
	client dnsop.Client
	dryRun bool
	// krb may be nil in tests that don't exercise /healthz, in which case
	// the handler falls back to reporting "ready" for backward compatibility
	// with the original health-check contract.
	krb *state.Kerberos
}

func NewHandlers(client dnsop.Client, dryRun bool) *Handlers {
	return &Handlers{client: client, dryRun: dryRun}
}

// NewHandlersWithState wires the live Kerberos state container into /healthz
// so the endpoint reflects whether the background kinit-refresh goroutine is
// healthy. Use this in production; the simpler NewHandlers stays around for
// the existing test suite.
func NewHandlersWithState(client dnsop.Client, dryRun bool, krb *state.Kerberos) *Handlers {
	return &Handlers{client: client, dryRun: dryRun, krb: krb}
}

func (h *Handlers) Records(w http.ResponseWriter, r *http.Request) {
	var req RecordsRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, dnsop.RecordsResult{
			OK: false, Phase: "dns-send", Message: "bad json: " + err.Error(), Retryable: false,
		})
		return
	}
	res := h.client.AXFR(req.Host, req.Port, req.Zone)
	writeJSON(w, http.StatusOK, res)
}

func (h *Handlers) Apply(w http.ResponseWriter, r *http.Request) {
	var req ApplyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, dnsop.ApplyResult{
			OK: false, Phase: "dns-send", Message: "bad json: " + err.Error(), Retryable: false,
		})
		return
	}
	if h.dryRun {
		log.Printf("[dry-run] would apply zone=%s changes=%d prereqs=%d",
			req.Zone, len(req.Changes), len(req.Prerequisites))
		writeJSON(w, http.StatusOK, dnsop.ApplyResult{OK: true})
		return
	}
	res := h.client.Update(req.Host, req.Port, req.Zone, req.Prerequisites, req.Changes)
	writeJSON(w, http.StatusOK, res)
}

// Healthz reports the current Kerberos refresh state. Status codes:
//   - 200 with ok=true when the most recent kinit succeeded ("ready").
//   - 503 with ok=false when the most recent kinit failed ("expired") or no
//     refresh has run yet ("unknown"). The sidecar keeps serving so a probe
//     can drain traffic without killing the container — recovery on the next
//     refresh tick will flip the response back to 200.
func (h *Handlers) Healthz(w http.ResponseWriter, r *http.Request) {
	if h.krb == nil {
		writeJSON(w, http.StatusOK, HealthResponse{
			OK: true, Kerberos: "ready", Detail: "",
		})
		return
	}
	status, detail, _ := h.krb.Snapshot()
	ok := status == state.StatusReady
	httpStatus := http.StatusOK
	if !ok {
		httpStatus = http.StatusServiceUnavailable
	}
	writeJSON(w, httpStatus, HealthResponse{
		OK:       ok,
		Kerberos: string(status),
		Detail:   detail,
	})
}

func writeJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("content-type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
