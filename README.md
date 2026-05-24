# ddo-rfc2136

A Go webhook provider for [`kubernetes-sigs/external-dns`](https://github.com/kubernetes-sigs/external-dns) that speaks RFC 2136 DNS UPDATE + RFC 3645 GSS-TSIG against Active Directory DNS. Designed to run alongside [`docker-dns-operator`](https://github.com/mrkhachaturov/docker-dns-operator) as a sidecar — but the wire contract is the standard external-dns webhook v1, so any controller that supports it works.

## Why this exists

Node has no mature library for GSS-TSIG. Go does: `github.com/miekg/dns` + `github.com/bodgit/tsig/gss`. This sidecar owns the entire DNS UPDATE protocol layer plus all RFC 2136-specific bookkeeping (DC failover, per-zone serialisation, AXFR caching, ownership tracking, collision detection) so the upstream controller can stay protocol-agnostic.

## Wire contract

The sidecar implements the external-dns webhook provider v1 contract:

| Method | Path | Body | Response |
|---|---|---|---|
| GET | `/` | — | `{ "filters": ["<zone1>", ...] }` |
| GET | `/records` | — | `[]Endpoint` (all managed records, with `labels.owner` populated) |
| POST | `/records` | `Changes` `{ create, updateOld, updateNew, delete: []Endpoint }` | 204 on success, 4xx/5xx with `{"error": "..."}` body |
| POST | `/adjustendpoints` | `[]Endpoint` | echo (no-op) |
| GET | `/healthz` | — | 200 `{ok:true, kerberos:"ready"}` or 503 with `kerberos:"expired"|"unknown"` |

The Accept/Content-Type header for `/`, `/records`, `/adjustendpoints` is `application/external.dns.webhook+json;version=1`.

`Endpoint` mirrors `sigs.k8s.io/external-dns/endpoint.Endpoint`:

- `dnsName`, `recordType`, `recordTTL`, `targets`, `labels`, `setIdentifier`, `providerSpecific`
- Per record type, `targets` carries one element per record:
  - `A` / `AAAA`: an IP literal
  - `CNAME` / `NS`: a hostname (trailing dot optional)
  - `MX`: `"<priority> <server>"` in canonical zone-file form
- `TXT` records are not directly exposed — the sidecar manages an ownership TXT internally per data record (see below).

## Ownership-TXT bridge

For every data record `X` at name `N`, the sidecar maintains a sibling `TXT` record at `ddo-<lower(X)>.N` with value `"owned-by=<PROJECT_LABEL>:<INSTANCE_ID>"`. This bridge serves two purposes:

1. **Persistence of ownership across restarts.** The sidecar holds no on-disk state; on every `GET /records` it AXFRs each zone, then walks the dump and emits an Endpoint for every data record whose sibling ownership TXT matches our label.
2. **Collision protection on writes.** Creates require an `NXRRSET` prerequisite on the ownership TXT (so a second operator instance can't silently overwrite a record that another instance owns). Updates and deletes require `YXRRSET` on the ownership TXT (so we refuse to touch a record we didn't create).

The TXT convention is stable — records written by previous versions of `docker-dns-operator` keep working. The sidecar tolerates "orphan" ownership TXTs (where a delete crashed between the data record and the TXT) by skipping the TXT prerequisite on a subsequent recreate and logging a warning.

## Required env vars

| Variable | Description |
|----------|-------------|
| `RFC2136_KERBEROS_REALM` | Kerberos realm (uppercase). |
| `RFC2136_KERBEROS_PRINCIPAL` | Service principal, e.g. `svc-dns@CORP.EXAMPLE.COM`. |
| `RFC2136_HOSTS` | Comma-separated FQDNs of writable DCs (failover order). IPs and bare labels are rejected — Kerberos needs a real SPN. |
| `RFC2136_ZONES` | Comma-separated zone names (no trailing dot). Used for AXFR targets and for routing inbound endpoints. |

## Optional env vars

| Variable | Default | Notes |
|---|---|---|
| `RFC2136_PORT` | `53` | DNS port. |
| `RFC2136_KRB5_CONF` | `/etc/krb5.conf` | Path to krb5.conf. |
| `WEBHOOK_LISTEN` | `:9090` | HTTP bind address. |
| `RFC2136_DRY_RUN` | `false` | If `true`, log changes but don't send UPDATE. |
| `RFC2136_AXFR_ENABLED` | `true` | If `false`, `GET /records` returns `[]` and the controller relies on UPDATE prerequisites for collision detection. |
| `RFC2136_DEFAULT_TTL` | `3600` | TTL applied when an Endpoint comes in without one. |
| `RFC2136_MIN_TTL` | `60` | Floor for any inbound TTL. |
| `RFC2136_CIRCUIT_BREAKER_THRESHOLD` | `3` | Consecutive failing cycles before a DC's circuit opens. |
| `RFC2136_DOMAIN_FILTER` | `""` | Comma-separated FQDN suffixes; non-matching endpoints are skipped. Empty = no filter. |
| `RFC2136_AXFR_TIMEOUT_SECONDS` | `30` | Per-AXFR dial+read timeout. |
| `RFC2136_UPDATE_TIMEOUT_SECONDS` | `15` | Per-UPDATE dial+write+read timeout. |
| `RFC2136_KINIT_REFRESH_INTERVAL` | `12h` | Background TGT refresh cadence. |
| `PROJECT_LABEL` | `docker-dns-operator` | First half of the ownership label `<project>:<instance>`. |
| `INSTANCE_ID` | `1` | Second half of the ownership label. Use different IDs when multiple controller instances target the same zone. |

## AD authentication — pick exactly one

The sidecar needs a way to get a Kerberos TGT at startup. Four mutually-exclusive sources are supported; set **exactly one**:

| Variable | When to use |
|----------|-------------|
| `RFC2136_AD_PASSWORD` | Simplest. Service-account password as an env string. Equivalent to k8s external-dns `--rfc2136-kerberos-password`. |
| `RFC2136_AD_PASSWORD_FILE` | Same as above but read from a file path (Docker secret pattern). |
| `RFC2136_KEYTAB_FILE` | Keytab mounted at a path (Docker secret or volume). Use when AD policy forbids password-based pre-auth, or when defense-in-depth matters (the keytab contains derived keys, not the plaintext password). |
| `RFC2136_KEYTAB_BASE64` | Keytab as base64-encoded bytes. Decoded into a `0600` temp file at startup. Use when your secret store can only return strings. |

Setting more than one is rejected at startup so misconfiguration fails fast.

### Password mode (recommended for most users)

```bash
RFC2136_KERBEROS_REALM=CORP.EXAMPLE.COM
RFC2136_KERBEROS_PRINCIPAL=svc-dns@CORP.EXAMPLE.COM
RFC2136_AD_PASSWORD_FILE=/run/secrets/ad_password   # or RFC2136_AD_PASSWORD=<plaintext>
```

Behind the scenes the sidecar runs `kinit <principal>` and pipes the password via stdin. The TGT is refreshed every `RFC2136_KINIT_REFRESH_INTERVAL` (default 12h).

### Keytab mode (defense-in-depth)

Generate a keytab on a Domain Controller using the helper script:

```powershell
.\scripts\New-ADKeytab.ps1 `
  -Principal "svc-dns@CORP.EXAMPLE.COM" `
  -MapUser   "CORP\svc-dns" `
  -OutFile   "C:\Temp\svc-dns.keytab"
```

The script wraps `ktpass.exe` with safe defaults (`-crypto AES256-SHA1 -ptype KRB5_NT_PRINCIPAL`), prompts for the password (no plaintext on disk), and optionally prints the base64 of the keytab for env-only secret stores via `-EmitBase64`.

## Build

```bash
go build -o ./bin/webhook ./cmd/webhook
go test ./...
```

## Run locally

```bash
docker build -t ddo-rfc2136:dev .
docker run --rm \
  -e WEBHOOK_LISTEN=:9090 \
  -e RFC2136_KERBEROS_REALM=CORP.EXAMPLE.COM \
  -e RFC2136_KERBEROS_PRINCIPAL=svc-dns@CORP.EXAMPLE.COM \
  -e RFC2136_HOSTS=dc01.corp.example.com,dc02.corp.example.com \
  -e RFC2136_ZONES=corp.example.com \
  -e RFC2136_KEYTAB_FILE=/keytab/svc-dns.keytab \
  -v $(pwd)/test/keytab:/keytab:ro \
  -v $(pwd)/test/krb5.conf:/etc/krb5.conf:ro \
  -p 127.0.0.1:9090:9090 \
  ddo-rfc2136:dev
```

## Failure model

- Each DC has a per-host circuit breaker with exponential backoff capped at 1h. Failing AXFRs increment the streak; a single successful cycle resets it.
- Each zone is "pinned" to its last successful DC. Failover walks remaining available DCs in `RFC2136_HOSTS` order on transient errors.
- Per-zone UPDATEs are serialised — one in-flight UPDATE per zone at a time.
- AXFR is all-or-nothing: a partial transfer or missing trailing SOA fails the whole zone for the cycle.
- TSIG quirks observed against AD (response-TSIG verify failing after a NOERROR commit) are treated as success and logged as a warning. See `internal/dnsop/client_real.go` for details.
