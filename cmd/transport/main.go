package main

import (
	"log"
	"net/http"
	"time"

	"github.com/mrkhachaturov/docker-external-dns/transport-rfc2136/internal/api"
	"github.com/mrkhachaturov/docker-external-dns/transport-rfc2136/internal/config"
	"github.com/mrkhachaturov/docker-external-dns/transport-rfc2136/internal/dnsop"
	"github.com/mrkhachaturov/docker-external-dns/transport-rfc2136/internal/kerberos"
)

func main() {
	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("config: %v", err)
	}
	log.Printf("rfc2136-transport listen=%s principal=%s dryRun=%v", cfg.Listen, cfg.Principal, cfg.DryRun)

	k := &kerberos.Kinit{Exec: kerberos.RealExec{}}
	if err := k.Run(cfg.Krb5Conf, cfg.Keytab, cfg.Principal); err != nil {
		log.Fatalf("kinit: %v", err)
	}
	log.Printf("kerberos ready")

	client, err := dnsop.NewRealClient(cfg.Realm, cfg.Principal, 30*time.Second, 15*time.Second)
	if err != nil {
		log.Fatalf("dns client: %v", err)
	}
	h := api.NewHandlers(client, cfg.DryRun)

	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", h.Healthz)
	mux.HandleFunc("POST /v1/records", h.Records)
	mux.HandleFunc("POST /v1/apply", h.Apply)

	srv := &http.Server{Addr: cfg.Listen, Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	log.Printf("listening on %s", cfg.Listen)
	if err := srv.ListenAndServe(); err != nil {
		log.Fatalf("http: %v", err)
	}
}
