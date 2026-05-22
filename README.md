# rfc2136-webhook

A small Go service that owns the RFC 2136 DNS UPDATE + RFC 3645 GSS-TSIG protocol layer for `docker-dns-operator`. The NestJS orchestrator talks to it over HTTP+JSON.

## Why this exists

Node has no mature library for GSS-TSIG. Go does: `github.com/miekg/dns` + `github.com/bodgit/tsig/gss`. The sidecar is ~500 lines of glue around those.

The "webhook" name aligns with the [Kubernetes external-dns](https://github.com/kubernetes-sigs/external-dns) ecosystem, which calls this kind of out-of-process provider a "webhook provider".

## Endpoints

| Method | Path | Purpose |
|--------|------|---------|
| `GET`  | `/healthz`    | Process + Kerberos liveness. |
| `POST` | `/v1/records` | AXFR a zone. Returns all records or `ok:false`. All-or-nothing. |
| `POST` | `/v1/apply`   | DNS UPDATE with prerequisites and changes. |

See `internal/api/types.go` for exact request/response shapes.

## Required env vars

| Variable | Description |
|----------|-------------|
| `RFC2136_KERBEROS_REALM` | Kerberos realm (uppercase). |
| `RFC2136_KERBEROS_PRINCIPAL` | Service principal, e.g. `svc-dns@CORP.EXAMPLE.COM`. |
| `RFC2136_KEYTAB_FILE` | Path inside this container to the keytab. |
| `RFC2136_KRB5_CONF` | Path to `krb5.conf` (default `/etc/krb5.conf`). |
| `WEBHOOK_LISTEN` | Bind address (default `:9090`). |
| `RFC2136_DRY_RUN` | If `true`, log changes but do not send DNS UPDATE. |

## Build

```bash
go build -o ./bin/webhook ./cmd/webhook
go test ./...
```

## Run locally

```bash
docker build -t docker-dns-operator-webhook:dev .
docker run --rm \
  -e WEBHOOK_LISTEN=:9090 \
  -e RFC2136_KERBEROS_REALM=CORP.EXAMPLE.COM \
  -e RFC2136_KERBEROS_PRINCIPAL=svc-dns@CORP.EXAMPLE.COM \
  -e RFC2136_KEYTAB_FILE=/keytab/svc-dns.keytab \
  -v $(pwd)/test/keytab:/keytab:ro \
  -v $(pwd)/test/krb5.conf:/etc/krb5.conf:ro \
  -p 127.0.0.1:9090:9090 \
  docker-dns-operator-webhook:dev
```

## Failure model

Responses are typed with `phase` and `retryable` fields so the orchestrator can decide whether to fail over to the next DC. The sidecar holds no per-call state — all routing decisions live in the orchestrator.
