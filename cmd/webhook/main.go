package main

import (
	"context"
	"log"
	"net/http"
	"os/signal"
	"syscall"
	"time"

	"github.com/mrkhachaturov/ddo-rfc2136/internal/api"
	"github.com/mrkhachaturov/ddo-rfc2136/internal/config"
	"github.com/mrkhachaturov/ddo-rfc2136/internal/dnsop"
	"github.com/mrkhachaturov/ddo-rfc2136/internal/kerberos"
	"github.com/mrkhachaturov/ddo-rfc2136/internal/state"
)

func main() {
	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("config: %v", err)
	}
	authMode := "keytab"
	if cfg.Password != "" {
		authMode = "password"
	}
	log.Printf("rfc2136-webhook listen=%s principal=%s authMode=%s dryRun=%v kinitRefresh=%v",
		cfg.Listen, cfg.Principal, authMode, cfg.DryRun, cfg.KinitRefreshInterval)

	k := &kerberos.Kinit{Exec: kerberos.RealExec{}}
	var kinitErr error
	if cfg.Password != "" {
		kinitErr = k.RunWithPassword(cfg.Krb5Conf, cfg.Principal, cfg.Password)
	} else {
		kinitErr = k.Run(cfg.Krb5Conf, cfg.Keytab, cfg.Principal)
	}
	if kinitErr != nil {
		// Startup kinit must succeed — a bad keytab or unreachable KDC at
		// boot is a config error worth failing fast on. Subsequent refresh
		// failures degrade /healthz without exiting.
		log.Fatalf("kinit: %v", kinitErr)
	}
	log.Printf("kerberos ready")

	krbState := state.NewKerberos()
	krbState.MarkReady(time.Now())

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	refresher := &kerberos.Refresher{
		Kinit:     k,
		Krb5Conf:  cfg.Krb5Conf,
		Keytab:    cfg.Keytab,
		Password:  cfg.Password,
		Principal: cfg.Principal,
		Interval:  cfg.KinitRefreshInterval,
		State:     krbState,
	}
	go func() {
		if err := refresher.Run(ctx); err != nil {
			log.Printf("kinit refresher exited: %v", err)
		}
	}()

	client, err := dnsop.NewRealClient(cfg.Realm, cfg.Principal, 30*time.Second, 15*time.Second)
	if err != nil {
		log.Fatalf("dns client: %v", err)
	}
	h := api.NewHandlersWithState(client, cfg.DryRun, krbState)

	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", h.Healthz)
	mux.HandleFunc("POST /v1/records", h.Records)
	mux.HandleFunc("POST /v1/apply", h.Apply)

	srv := &http.Server{Addr: cfg.Listen, Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	log.Printf("listening on %s", cfg.Listen)

	go func() {
		<-ctx.Done()
		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer shutdownCancel()
		_ = srv.Shutdown(shutdownCtx)
	}()

	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatalf("http: %v", err)
	}
}
