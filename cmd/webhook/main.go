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
	"github.com/mrkhachaturov/ddo-rfc2136/internal/orchestrator"
	"github.com/mrkhachaturov/ddo-rfc2136/internal/state"
)

func main() {
	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("config: %v", err)
	}
	log.Printf("ddo-rfc2136 listen=%s authMode=%s dryRun=%v hosts=%v zones=%v axfr=%v",
		cfg.Listen, cfg.AuthMode, cfg.DryRun, cfg.Hosts, cfg.Zones, cfg.AxfrEnabled)

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	client, krbState := setupAuth(ctx, cfg)

	orc := orchestrator.New(orchestrator.Options{
		Hosts:                   cfg.Hosts,
		Port:                    cfg.Port,
		Zones:                   cfg.Zones,
		AxfrEnabled:             cfg.AxfrEnabled,
		DefaultTTL:              cfg.DefaultTTL,
		MinTTL:                  cfg.MinTTL,
		CircuitBreakerThreshold: cfg.CircuitBreakerThreshold,
		DomainFilter:            cfg.DomainFilter,
		DryRun:                  cfg.DryRun,
	}, client)

	h := api.NewHandlers(orc, krbState)

	mux := http.NewServeMux()
	mux.HandleFunc("GET /", h.Negotiate)
	mux.HandleFunc("GET /records", h.Records)
	mux.HandleFunc("POST /records", h.ApplyChanges)
	mux.HandleFunc("POST /adjustendpoints", h.AdjustEndpoints)
	mux.HandleFunc("GET /healthz", h.Healthz)

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

// setupAuth builds the DNS client for the configured auth mode.
//
// Only gss-tsig has a credential to acquire and keep alive, so only it runs
// kinit and the background refresher. The TSIG modes return a nil health
// source: api.Handlers reads that as "nothing to report", which beats faking a
// ready Kerberos that does not exist.
func setupAuth(ctx context.Context, cfg config.Config) (dnsop.Client, *state.Kerberos) {
	switch cfg.AuthMode {
	case config.AuthHMACTSIG:
		log.Printf("auth: hmac-tsig key=%s algorithm=%s", cfg.TSIGKeyName, cfg.TSIGAlgorithm)
		return dnsop.NewTSIGClient(cfg.TSIGKeyName, cfg.TSIGSecret, cfg.TSIGAlgorithm,
			false, cfg.AxfrTimeout, cfg.UpdateTimeout), nil

	case config.AuthInsecure:
		log.Printf("auth: WARN insecure — UPDATEs go out unsigned; the server's network ACL is the only thing authorising us")
		return dnsop.NewTSIGClient("", "", "", true, cfg.AxfrTimeout, cfg.UpdateTimeout), nil
	}

	credential := "keytab"
	if cfg.Password != "" {
		credential = "password"
	}
	log.Printf("auth: gss-tsig principal=%s credential=%s kinitRefresh=%v", cfg.Principal, credential, cfg.KinitRefreshInterval)

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

	refresher := &kerberos.Refresher{
		Kinit:     k,
		Krb5Conf:  cfg.Krb5Conf,
		Keytab:    cfg.Keytab,
		Password:  cfg.Password,
		Principal: cfg.Principal,
		Interval:  cfg.KinitRefreshInterval,
		State:     krbState,
		Lifetime:  kerberos.CCacheLifetime{},
	}
	go func() {
		if err := refresher.Run(ctx); err != nil {
			log.Printf("kinit refresher exited: %v", err)
		}
	}()

	client, err := dnsop.NewRealClient(cfg.Realm, cfg.Principal, cfg.AxfrTimeout, cfg.UpdateTimeout)
	if err != nil {
		log.Fatalf("dns client: %v", err)
	}
	return client, krbState
}
