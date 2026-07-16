# Changelog

All notable changes to **ddo-rfc2136** are recorded here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

ddo-rfc2136 is a webhook sidecar for [docker-dns-operator](https://github.com/mrkhachaturov/docker-dns-operator), implementing the [external-dns webhook provider v1 contract](https://kubernetes-sigs.github.io/external-dns/latest/docs/tutorials/webhook-provider/) against any authoritative server that speaks RFC 2136 — Active Directory (GSS-TSIG), BIND, Knot, PowerDNS and Technitium (HMAC-TSIG). The same sidecar works with the upstream kubernetes-sigs/external-dns controller.

## [Unreleased]

### Added
- **`RFC2136_AUTH_MODE` — the sidecar is no longer AD-only.** RFC 2136 is the same wire protocol everywhere; only the signature on the message differed, and that was the sole thing tying this sidecar to Active Directory. Three modes now: `gss-tsig` (RFC 3645, Kerberos — what AD demands), `hmac-tsig` (RFC 8945 pre-shared key — what BIND, Knot, PowerDNS and Technitium speak) and `insecure` (unsigned, authorised by the server's network ACL alone, warns on every boot). One sidecar image now covers every self-hosted authoritative server rather than one vendor.

  **Defaults to `gss-tsig`, so existing AD deployments are unaffected** — they set no `RFC2136_AUTH_MODE` and behave exactly as before.

- `RFC2136_TSIG_KEY_NAME`, `RFC2136_TSIG_SECRET` / `RFC2136_TSIG_SECRET_FILE` and `RFC2136_TSIG_ALGORITHM` (default `hmac-sha256`, one of `hmac-sha1|sha224|sha256|sha384|sha512`). The secret follows the same env-or-file pattern as the Kerberos password, so it can arrive as a Docker secret. The algorithm is validated at startup against the supported set rather than failing at the first UPDATE.

### Changed
- `RFC2136_HOSTS` **accepts IP literals outside `gss-tsig`**. The rejection existed because Kerberos can only target an FQDN with a matching SPN; plain TSIG resolves no SPN, and a Technitium or BIND box reached at `10.1.125.10` is entirely normal. IPs remain rejected under `gss-tsig`, where accepting one would mask a real misconfiguration.
- **Cross-mode settings are refused at startup, not ignored.** A stray `RFC2136_AD_PASSWORD` under `hmac-tsig`, or `RFC2136_TSIG_KEY_NAME` under `gss-tsig`, means someone believes they configured auth that is never read.
- Under `hmac-tsig` and `insecure` the sidecar never shells out to `kinit`, never starts the TGT refresher, and reports health without reference to Kerberos.

### Fixed
- **Dependency updates were deadlocked and nothing could merge.** `bodgit/tsig` 1.3.1 requires Go >= 1.25 while the Dockerfile pinned `golang:1.22-alpine`, so the docker build failed on the tsig bump while the Go bump sat in a separate PR — neither could go green alone. Bumped together: `bodgit/tsig` 1.2.2 → 1.3.1, `miekg/dns` 1.1.62 → 1.1.72, `jcmturner/gokrb5` 8.4.3 → 8.4.4, `golang.org/x/crypto` 0.25 → 0.54, `golang.org/x/net` 0.27 → 0.57, go directive 1.22 → 1.25, `golang:1.26-alpine`, `alpine:3.24`. (tsig v1.2.2 dates from 2023-02-13 and was pinned here on 2026-05-22 — two days after 1.3.1 shipped.)

### Removed
- **The CGO build.** `CGO_ENABLED=1` plus `build-base`/`krb5-dev`/`pkgconfig` did nothing: `bodgit/tsig/gss` picks its GSSAPI implementation by build tag, and the pure-Go gokrb5 one is the default — the C one (`openshift/gssapi`) only compiles under `-tags apcera`, which was never set. Verified by building with `CGO_ENABLED=1` on a host with no krb5 headers and finding no `openshift/gssapi` in either binary. The image now ships a static binary. The runtime `krb5` package stays: `kinit` is a real dependency of `gss-tsig` mode.

## [0.2.0] — 2026-06-07

### Changed
- TGT refresh cadence is now **self-tuning from the real ticket lifetime** instead of a fixed period (#9). After each successful `kinit` the sidecar reads the issued TGT's `endtime` from the ccache and schedules the next refresh at `now + 0.5*(endtime-now)`. `RFC2136_KINIT_REFRESH_INTERVAL` (default lowered from 12h to **8h**) is now an **upper bound only**: `interval = min(configuredOrDefault, 0.5*actualLifetime)`. Against a default Active Directory (10h `MaxTicketAge`) the old 12h default left a 2h expiry window every cycle; the cadence now tracks whatever lifetime the KDC actually grants, so hardened policies (4h tickets, etc.) tighten automatically. A failed refresh now retries on a short 1-5 min backoff rather than waiting a full interval, so one transient KDC error can't open an expiry window.

### Fixed
- Wildcard records (`*.dev.example.com`) no longer silently orphan **on RFC2136 servers that accept wildcard dynamic updates** (e.g. BIND). The paired ownership-TXT marker previously became `ddo-a.*.dev.example.com` — a `*` in a non-leftmost label, which is invalid — so the read-back path never saw the record and the operator re-applied it every cycle. The marker is now encoded star-free and reversibly: a wildcard data name strips the leading `*.` and folds the wildcard into the type sentinel (`*.dev.example.com` type A → marker `ddo-a-wildcard.dev.example.com`); the inverse on read restores `*.dev.example.com`/A. The data record name itself is unchanged (leftmost `*` is legal DNS). Non-wildcard markers keep the exact `ddo-<type>.<name>` shape, so markers already persisted round-trip unchanged.

  > **Windows AD DNS caveat.** Windows DNS Server **refuses wildcard records via RFC 2136 dynamic update** (`UPDATE → REFUSED`), even though it accepts them via manual/PowerShell creation and resolves them fine. This is a Windows DNS policy, not a sidecar limitation — verified with a plain `nsupdate` (no GSS-TSIG, no operator): a non-wildcard update succeeds while `*.name` returns `REFUSED`. **To serve a wildcard against an AD-backed zone, create it manually in AD (or delegate the subzone), or route the wildcard to a provider that accepts it (e.g. MikroTik via `regexp`).** The operator/sidecar will keep retrying the refused update and log it each cycle.
- `GET /` now emits the domain filter as `include` (per external-dns `endpoint.DomainFilter`) instead of the legacy `filters` key, which upstream parses as an unset filter — previously every record was routed through the sidecar regardless of zone.

## [0.1.1] — 2026-05-25

### Added
- `RFC2136_KEYTAB_BASE64_FILE` — base64-encoded keytab delivered as a file (e.g. a Docker secret holding the base64 string). The contents are read at startup and decoded into the same `0600` temp keytab as `RFC2136_KEYTAB_BASE64`. Useful when your secret store can only mount strings as files (1Password Connect → Docker secret, Vault Agent file sink, etc.).
- `RFC2136_KERBEROS_PRINCIPAL_FILE` — principal name read from a file. Mutually exclusive with `RFC2136_KERBEROS_PRINCIPAL`. Lets the service-account identity be delivered via Docker secret instead of as a `docker service inspect`-visible env var.
- `HEALTHCHECK` directive in the Dockerfile — busybox `wget --spider http://127.0.0.1:9090/healthz`. The endpoint already existed; the image now wires it as the container-level liveness probe.

### Changed
- `resolveAuth` now lists five mutually-exclusive secret sources (was four). Misconfiguration error message updated to enumerate them all.

[Unreleased]: https://github.com/mrkhachaturov/ddo-rfc2136/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/mrkhachaturov/ddo-rfc2136/compare/v0.1.1...v0.2.0
[0.1.1]: https://github.com/mrkhachaturov/ddo-rfc2136/releases/tag/v0.1.1

## [0.1.0] — 2026-05-25

First tagged release.

### Added
- External-dns webhook provider v1 endpoints: `GET /`, `GET /records`, `POST /records`, `POST /adjustendpoints`, `GET /healthz`.
- RFC 2136 UPDATE and AXFR against Active Directory, signed with GSS-TSIG. The Kerberos/TSIG protocol layer is owned entirely by the sidecar — the operator never reads the keytab and never obtains tickets.
- Two auth modes (pick exactly one):
  - **Password** — sidecar runs `kinit <principal>` with the password piped via stdin (matches k8s external-dns).
  - **Keytab** — base64-encoded keytab (via `RFC2136_KEYTAB_BASE64`) decoded into a 0600 temp file at startup, or `RFC2136_KEYTAB_FILE` for a mounted secret.
- Background TGT refresh on `RFC2136_KINIT_REFRESH_INTERVAL`; `/healthz` reports `kerberos: expired` (HTTP 503) on refresh failure.
- Multi-DC failover: comma-separated `RFC2136_HOSTS` are tried in order with a per-DC circuit breaker (`RFC2136_CIRCUIT_BREAKER_THRESHOLD`) and per-zone DC pinning so successive writes hit the same DC until it falls over.
- AXFR-disabled mode (`RFC2136_AXFR_ENABLED=false`) for environments where AD blocks zone transfers. Drift detection is reduced; writes rely on UPDATE prerequisites (NXRRSET / YXRRSET).
- Dry-run mode (`RFC2136_DRY_RUN=true`) — logs intended UPDATEs without applying. Useful for first run against a new DC.
- Domain filter (`RFC2136_DOMAIN_FILTER`) — comma-separated name suffixes, narrows which entries are accepted without narrowing `RFC2136_ZONES`.
- Records supported: A, AAAA, CNAME, MX, NS.
- Ownership round-trip through paired TXT marker `ddo-<type>.<name>` with value `owned-by=<labels.owner>` (the external-dns convention for raw DNS). The sidecar persists `labels.owner` from the request verbatim — no env-derived ownership value, so two operators with different `INSTANCE_ID`s coexist safely.
- Hostnames in `RFC2136_HOSTS` validated at startup: IPs and short names are rejected (AD's Kerberos service principal is bound to the host name you contact).

### Fixed
- Trailing dot drift on CNAME / NS / MX read paths. AD canonicalises hostname targets with a trailing dot; the operator stamps wire values without one. Without normalisation on read, the operator's string-compare diff sees drift every cycle and re-applies the same UPDATE forever. The read path now strips a single trailing dot from these record types; A/AAAA are untouched (IP literals have no trailing-dot semantics).

### Notes
- Distroless image, pure Go, CGO disabled. Kerberos client uses `github.com/jcmturner/gokrb5` — no MIT-Kerberos shared library needed at runtime.
- See [README.md](README.md) for env vars and deployment examples.

[0.1.0]: https://github.com/mrkhachaturov/ddo-rfc2136/releases/tag/v0.1.0
