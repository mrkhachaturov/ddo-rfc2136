# ddo-rfc2136

The Active Directory DNS sidecar for [docker-dns-operator](https://github.com/mrkhachaturov/docker-dns-operator). It owns the DNS UPDATE conversation with your domain controllers. The operator tells it which records should exist; this process writes them via RFC 2136 DNS UPDATE secured with RFC 3645 GSS-TSIG (Kerberos).

This is the part that has to be written in Go. Node has no mature GSS-TSIG implementation; Go does (`github.com/miekg/dns` + `github.com/bodgit/tsig/gss`). Pulling it out as its own process keeps the operator language-agnostic and the AD code in a runtime that can actually do the auth.

## What it does

Three jobs, one binary:

- Apply changes the operator sends (create / update / delete records) using DNS UPDATE with `NXRRSET` / `YXRRSET` prerequisites so two operators can't silently overwrite each other.
- AXFR each managed zone on read so the operator can see drift and reconcile against reality, not against in-memory state.
- Run Kerberos: `kinit` at startup, refresh the TGT in the background, fail loudly on auth issues instead of silently going stale.

It also handles per-DC failover (pin a zone to its last successful DC, walk the rest of `RFC2136_HOSTS` on transient errors) and per-DC circuit breakers, because AD environments routinely have one DC misbehave while the rest are fine.

## How to configure

Required:

| Env | What it is |
|---|---|
| `RFC2136_KERBEROS_REALM` | Kerberos realm, uppercase (e.g. `CORP.EXAMPLE.COM`). |
| `RFC2136_KERBEROS_PRINCIPAL` | Service principal (`svc-dns@CORP.EXAMPLE.COM`). Mutually exclusive with `RFC2136_KERBEROS_PRINCIPAL_FILE` — set one or the other. |
| `RFC2136_KERBEROS_PRINCIPAL_FILE` | Path to a file containing the principal name. For Docker secret delivery (keeps the principal out of `docker service inspect` env output). |
| `RFC2136_HOSTS` | Comma-separated FQDNs of writable DCs, in failover order. IPs and bare labels are rejected; Kerberos needs a real SPN. |
| `RFC2136_ZONES` | Comma-separated zone names (no trailing dot). |

Optional:

| Env | Default | Notes |
|---|---|---|
| `RFC2136_PORT` | `53` | DNS port. |
| `RFC2136_KRB5_CONF` | `/etc/krb5.conf` | Path to `krb5.conf`. |
| `RFC2136_DRY_RUN` | `false` | Log changes but don't send UPDATE. Useful for dress rehearsals. |
| `RFC2136_AXFR_ENABLED` | `true` | If `false`, read returns `[]` and the operator relies entirely on UPDATE prerequisites for collision detection. |
| `RFC2136_DEFAULT_TTL` | `3600` | Used when the operator sends a record without a TTL. |
| `RFC2136_MIN_TTL` | `60` | Floor for any inbound TTL. |
| `RFC2136_CIRCUIT_BREAKER_THRESHOLD` | `3` | Consecutive failing cycles before a DC's circuit opens. |
| `RFC2136_DOMAIN_FILTER` | `""` | Comma-separated FQDN suffixes; non-matching records are skipped. Empty = no filter. |
| `RFC2136_AXFR_TIMEOUT_SECONDS` | `30` | Per-AXFR dial+read timeout. |
| `RFC2136_UPDATE_TIMEOUT_SECONDS` | `15` | Per-UPDATE dial+write+read timeout. |
| `RFC2136_KINIT_REFRESH_INTERVAL` | `12h` | Background TGT refresh cadence. |
| `WEBHOOK_LISTEN` | `:9090` | HTTP bind address. |

The sidecar has no env vars for any operator-identity concept. It does not read `PROJECT_LABEL`, `INSTANCE_ID`, or anything similar. The operator stamps its label on each request; the sidecar persists that value verbatim (see below).

## AD authentication: pick exactly one

The sidecar needs a way to get a Kerberos TGT at startup. Four sources are supported; set exactly one. More than one is rejected at startup so misconfiguration fails fast:

| Env | When to use |
|---|---|
| `RFC2136_AD_PASSWORD` | Simplest. Service-account password as an env string. |
| `RFC2136_AD_PASSWORD_FILE` | Same, read from a file path (Docker secret pattern). |
| `RFC2136_KEYTAB_FILE` | Keytab mounted at a path. Use when AD policy forbids password-based pre-auth or when defense-in-depth matters; the keytab contains derived keys, not the plaintext password. |
| `RFC2136_KEYTAB_BASE64` | Keytab as base64-encoded bytes. Decoded into a `0600` temp file at startup. For secret stores that can only return strings. |
| `RFC2136_KEYTAB_BASE64_FILE` | Same as `RFC2136_KEYTAB_BASE64` but the base64 string is read from a file path. Use when your secret store can only deliver strings as files (Docker secret holding a base64-encoded keytab, 1Password Connect → file sink, etc.). |

### Password mode

```bash
RFC2136_KERBEROS_REALM=CORP.EXAMPLE.COM
RFC2136_KERBEROS_PRINCIPAL=svc-dns@CORP.EXAMPLE.COM
RFC2136_AD_PASSWORD_FILE=/run/secrets/ad_password
```

The sidecar runs `kinit <principal>` and pipes the password via stdin. The TGT is refreshed every `RFC2136_KINIT_REFRESH_INTERVAL` (default 12 hours).

### Keytab mode

Generate the keytab on a Domain Controller using the helper script:

```powershell
.\scripts\New-ADKeytab.ps1 `
  -Principal "svc-dns@CORP.EXAMPLE.COM" `
  -MapUser   "CORP\svc-dns" `
  -OutFile   "C:\Temp\svc-dns.keytab"
```

The script wraps `ktpass.exe` with safe defaults (`-crypto AES256-SHA1 -ptype KRB5_NT_PRINCIPAL`), prompts for the password (no plaintext on disk), and can print a base64 dump of the keytab via `-EmitBase64` for env-only secret stores.

## How ownership tagging works

For every data record this sidecar writes at name `N` of type `X`, it also maintains a sibling TXT record at `ddo-<lower(X)>.N`. The TXT value is `"owned-by=<value>"`, where `<value>` is whatever `labels.owner` arrived in the operator's request — copied through verbatim. The sidecar does not read or compose ownership labels itself.

Two things fall out of this:

A second operator pointed at the same zone cannot silently overwrite records the first one owns. Creates carry an `NXRRSET` prerequisite on the ownership TXT; updates and deletes carry `YXRRSET` with the requesting operator's exact owner string. A wrong-owner write is rejected at the DNS UPDATE layer, not after the fact.

The sidecar holds no on-disk state. On every read it walks the AXFR dump, finds every data record that has a sibling ownership TXT, and surfaces both to the operator (with `labels.owner` populated from the TXT value, whatever it is). The operator decides which of those records belong to it. Unmanaged records — anything without a sibling ownership TXT — are not exposed.

If a delete crashes between removing the data record and removing the TXT, you get an "orphan" ownership TXT. The sidecar tolerates this on a subsequent recreate (skips the TXT prerequisite, logs a warning) so retries actually converge.

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

Worth knowing if you're going to operate this:

- Each DC has its own circuit breaker with exponential backoff capped at 1h. A single successful cycle resets the streak.
- Each zone is pinned to its last successful DC. Failover walks the remaining DCs in `RFC2136_HOSTS` order on transient errors.
- Per-zone UPDATEs are serialised. One in-flight UPDATE per zone at a time.
- AXFR is all-or-nothing. A partial transfer or missing trailing SOA fails the whole zone for that cycle.
- TSIG quirks observed against AD (response-TSIG verify failing after a `NOERROR` commit) are treated as success and logged as a warning. See `internal/dnsop/client_real.go` for the details.

## License

MIT.
