package api

import (
	"encoding/json"
	"log"
	"net/http"

	"github.com/mrkhachaturov/docker-external-dns/transport-rfc2136/internal/dnsop"
)

type Handlers struct {
	client dnsop.Client
	dryRun bool
}

func NewHandlers(client dnsop.Client, dryRun bool) *Handlers {
	return &Handlers{client: client, dryRun: dryRun}
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

func (h *Handlers) Healthz(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, HealthResponse{
		OK: true, Kerberos: "ready", Detail: "",
	})
}

func writeJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("content-type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
