# Changelog

All notable changes to **ddo-rfc2136** are recorded here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

ddo-rfc2136 is a webhook sidecar for [docker-dns-operator](https://github.com/mrkhachaturov/docker-dns-operator), implementing the [external-dns webhook provider v1 contract](https://kubernetes-sigs.github.io/external-dns/latest/docs/tutorials/webhook-provider/) against Active Directory DNS via GSS-TSIG-signed RFC 2136 UPDATEs. The same sidecar works with the upstream kubernetes-sigs/external-dns controller.

## [Unreleased]

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

[Unreleased]: https://github.com/mrkhachaturov/ddo-rfc2136/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/mrkhachaturov/ddo-rfc2136/releases/tag/v0.1.0
