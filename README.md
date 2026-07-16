# ddo-rfc2136

The RFC 2136 DNS sidecar for [docker-dns-operator](https://github.com/mrkhachaturov/docker-dns-operator). It owns the DNS UPDATE conversation with your authoritative servers. The operator tells it which records should exist; this process writes them via DNS UPDATE.

Any server that speaks RFC 2136 works: Active Directory, BIND, Knot, PowerDNS, Technitium. The wire protocol is the same everywhere — only the signature on the message differs, which is what `RFC2136_AUTH_MODE` selects:

| Mode | Signature | Who speaks it |
|---|---|---|
| `gss-tsig` (default) | RFC 3645 GSS-TSIG (Kerberos) | Active Directory — it accepts nothing else |
| `hmac-tsig` | RFC 8945 TSIG, pre-shared key | BIND, Knot, PowerDNS, Technitium |
| `insecure` | none | anything, authorised by network ACL alone |

The default is `gss-tsig` because that is what this sidecar shipped with. An existing AD deployment sets no `RFC2136_AUTH_MODE` and keeps working untouched.

This is the part that has to be written in Go. Node has no mature GSS-TSIG implementation; Go does (`github.com/miekg/dns` + `github.com/bodgit/tsig`). Pulling it out as its own process keeps the operator language-agnostic and the auth code in a runtime that can actually do it.

## What it does

Three jobs, one binary:

- Apply changes the operator sends (create / update / delete records) using DNS UPDATE with `NXRRSET` / `YXRRSET` prerequisites so two operators can't silently overwrite each other.
- AXFR each managed zone on read so the operator can see drift and reconcile against reality, not against in-memory state.
- Under `gss-tsig` only, run Kerberos: `kinit` at startup, refresh the TGT in the background, fail loudly on auth issues instead of silently going stale. The TSIG modes have no credential to acquire or keep alive, so they skip all of it.

It also handles per-server failover (pin a zone to its last successful server, walk the rest of `RFC2136_HOSTS` on transient errors) and per-server circuit breakers, because AD environments routinely have one DC misbehave while the rest are fine.

## How to configure

Required in every mode:

| Env | What it is |
|---|---|
| `RFC2136_HOSTS` | Comma-separated servers, in failover order. IP literals are accepted except under `gss-tsig`, where Kerberos needs an FQDN with a matching SPN. |
| `RFC2136_ZONES` | Comma-separated zone names (no trailing dot). |

Required under `gss-tsig` (the default):

| Env | What it is |
|---|---|
| `RFC2136_KERBEROS_REALM` | Kerberos realm, uppercase (e.g. `CORP.EXAMPLE.COM`). |
| `RFC2136_KERBEROS_PRINCIPAL` | Service principal (`svc-dns@CORP.EXAMPLE.COM`). Mutually exclusive with `RFC2136_KERBEROS_PRINCIPAL_FILE` — set one or the other. |
| `RFC2136_KERBEROS_PRINCIPAL_FILE` | Path to a file containing the principal name. For Docker secret delivery (keeps the principal out of `docker service inspect` env output). |

Required under `hmac-tsig`:

| Env | What it is |
|---|---|
| `RFC2136_TSIG_KEY_NAME` | Key name exactly as configured on the server. |
| `RFC2136_TSIG_SECRET` | Base64 shared secret. Mutually exclusive with `RFC2136_TSIG_SECRET_FILE`. |
| `RFC2136_TSIG_SECRET_FILE` | Same, read from a file path (Docker secret pattern). |

Settings belonging to another mode are **rejected at startup**, not ignored: a stray `RFC2136_AD_PASSWORD` under `hmac-tsig` means someone believes they configured auth that will never be read.

Optional:

| Env | Default | Notes |
|---|---|---|
| `RFC2136_AUTH_MODE` | `gss-tsig` | One of `gss-tsig`, `hmac-tsig`, `insecure`. |
| `RFC2136_TSIG_ALGORITHM` | `hmac-sha256` | `hmac-tsig` only. One of `hmac-sha1`, `hmac-sha224`, `hmac-sha256`, `hmac-sha384`, `hmac-sha512`. Checked at startup, not at the first UPDATE. |

| Env | Default | Notes |
|---|---|---|
| `RFC2136_PORT` | `53` | DNS port. |
| `RFC2136_KRB5_CONF` | `/etc/krb5.conf` | `gss-tsig` only. Path to `krb5.conf`. |
| `RFC2136_DRY_RUN` | `false` | Log changes but don't send UPDATE. Useful for dress rehearsals. |
| `RFC2136_AXFR_ENABLED` | `true` | If `false`, read returns `[]` and the operator relies entirely on UPDATE prerequisites for collision detection. |
| `RFC2136_DEFAULT_TTL` | `3600` | Used when the operator sends a record without a TTL. |
| `RFC2136_MIN_TTL` | `60` | Floor for any inbound TTL. |
| `RFC2136_CIRCUIT_BREAKER_THRESHOLD` | `3` | Consecutive failing cycles before a server's circuit opens. |
| `RFC2136_DOMAIN_FILTER` | `""` | Comma-separated FQDN suffixes; non-matching records are skipped. Empty = no filter. |
| `RFC2136_AXFR_TIMEOUT_SECONDS` | `30` | Per-AXFR dial+read timeout. |
| `RFC2136_UPDATE_TIMEOUT_SECONDS` | `15` | Per-UPDATE dial+write+read timeout. |
| `RFC2136_KINIT_REFRESH_INTERVAL` | `8h` | `gss-tsig` only. Upper bound on the background TGT refresh cadence. The actual cadence is derived per-ticket from the lifetime the KDC grants: `min(this, 0.5 * actual_TGT_lifetime)`. A failed refresh retries on a 1-5 min backoff. |
| `WEBHOOK_LISTEN` | `:9090` | HTTP bind address. |

The sidecar has no env vars for any operator-identity concept. It does not read `PROJECT_LABEL`, `INSTANCE_ID`, or anything similar. The operator stamps its label on each request; the sidecar persists that value verbatim (see below).

## Reads are not signed against Active Directory

Worth knowing before it surprises you: under `gss-tsig` the AXFR goes out **unsigned and comes back unverified**, by design.

Windows DNS does not do TSIG on zone transfers at all — there is no key setting for XFR in DNS Manager, `Set-DnsServerPrimaryZone`, the registry, or the `Dns-Zone` AD schema class, and Microsoft documents TSIG only for dynamic update. Transfers are authorised by the `SecureSecondaries` IP ACL and answered with no signature on any envelope. So there is nothing to verify, and asking `miekg/dns` to verify anyway just aborts the transfer.

That is safe here because reads and writes are protected differently. Every UPDATE is GSS-TSIG signed and carries `NXRRSET`/`YXRRSET` prerequisites the DC evaluates itself, so a forged transfer can at worst make the sidecar send UPDATEs that fail — it cannot make the DC apply one.

Two practical consequences: allow zone transfer to the sidecar's IP (`SecureSecondaries` + `SecondaryServers`), or `GET /records` returns `[]` and the operator loses its view of drift. And check that the ACL is not `TransferAnyServer`, or anyone who can reach the DC on TCP/53 can dump every internal name.

`hmac-tsig` is the opposite: those servers do sign transfers, so that path signs and verifies.

## hmac-tsig: BIND, Knot, PowerDNS, Technitium

```bash
RFC2136_AUTH_MODE=hmac-tsig
RFC2136_HOSTS=10.1.125.10
RFC2136_ZONES=example.com
RFC2136_TSIG_KEY_NAME=ddo
RFC2136_TSIG_SECRET_FILE=/run/secrets/tsig
RFC2136_TSIG_ALGORITHM=hmac-sha256
```

No Kerberos, no `kinit`, no `krb5.conf`, no TGT to keep alive. The key name must match the server's exactly — a mismatch surfaces as `BADKEY`, a wrong secret as `BADSIG`, and neither is retried, because the next tick would be just as wrong.

Server side you need two things: allow dynamic updates for the zone bound to this key, and allow zone transfer to the same key — the sidecar reads via AXFR, and without it `GET /records` returns `[]` and the operator loses its view of drift. On Technitium that is *Zone Options → Dynamic Updates → Allow* with a security policy naming the key, plus the key in *Zone Transfer → TSIG key names*. Technitium's security policy is per key, per domain and per record type, so the key can be scoped to exactly what this instance manages.

## insecure

`RFC2136_AUTH_MODE=insecure` signs nothing. Anyone who can reach the server's UPDATE port and passes its network ACL can write the same records. It warns on every boot. Use it only where the ACL is the real control.

## AD authentication (gss-tsig): pick exactly one

The sidecar needs a way to get a Kerberos TGT at startup. Four sources are supported; set exactly one. More than one is rejected at startup so misconfiguration fails fast:

| Env | When to use |
|---|---|
| `RFC2136_AD_PASSWORD` | Simplest. Service-account password as an env string. |
| `RFC2136_AD_PASSWORD_FILE` | Same, read from a file path (Docker secret pattern). |
| `RFC2136_KEYTAB_FILE` | Keytab mounted at a path. Use when AD policy forbids password-based pre-auth or when defense-in-depth matters; the keytab contains derived keys, not the plaintext password. |
| `RFC2136_KEYTAB_BASE64` | Keytab as base64-encoded bytes. Decoded into a `0600` temp file at startup. For secret stores that can only return strings. |
| `RFC2136_KEYTAB_BASE64_FILE` | Same as `RFC2136_KEYTAB_BASE64` but the base64 string is read from a file path. Use when your secret store can only deliver strings as files (Docker secret holding a base64-encoded keytab, 1Password Connect → file sink, etc.). |

### The zone must be "Secure only"

Set the AD-integrated zone's dynamic-update policy to **Secure only**, not "Nonsecure and secure".

This is not hardening advice — it is what makes `gss-tsig` do anything. On "Nonsecure and secure" AD takes the non-secure path: it applies the record **without checking your signature at all**, leaves the object owned by `SYSTEM` instead of your principal, and — having never run its TSIG code — returns your own request MIC verbatim rather than signing a reply. The record appears, so nothing looks broken, but every write is unauthenticated and no ACL protects it. Two operators sharing a zone cannot rely on ownership, and nothing stops a third party on the network from overwriting the same names.

The tell is a warning on **every** UPDATE that the server did not sign its reply (see "Failure model"). Flip the zone to Secure only and it stops immediately: AD verifies the signature, signs its reply, and stamps the record with your principal as owner.

```powershell
Get-DnsServerZone -Name example.com | Select-Object ZoneName, ZoneType, DynamicUpdate
Set-DnsServerPrimaryZone -Name example.com -DynamicUpdate Secure
```

Secure dynamic update also requires the principal to have create/write rights on the zone (Domain Admins and members of `DnsAdmins` have them by default; a plain service account needs them granted).

### Password mode

```bash
RFC2136_KERBEROS_REALM=CORP.EXAMPLE.COM
RFC2136_KERBEROS_PRINCIPAL=svc-dns@CORP.EXAMPLE.COM
RFC2136_AD_PASSWORD_FILE=/run/secrets/ad_password
```

The sidecar runs `kinit <principal>` and pipes the password via stdin. The TGT is refreshed on a self-tuning cadence derived from the lifetime the KDC actually issues (`min(RFC2136_KINIT_REFRESH_INTERVAL, 0.5 * actual_TGT_lifetime)`); `RFC2136_KINIT_REFRESH_INTERVAL` (default 8h) is only the ceiling.

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
- A `NOERROR` whose reply we cannot verify is reported as applied and logged as a loud warning: the record is really there, but the server never authenticated us. See "The zone must be Secure only" below.

## License

MIT.
