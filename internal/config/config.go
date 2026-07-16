package config

import (
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/miekg/dns"
)

// AuthMode selects how UPDATE and AXFR messages are authenticated. The wire
// protocol is RFC 2136 either way; only the signature on the message differs.
type AuthMode string

const (
	// AuthGSSTSIG is RFC 3645 GSS-TSIG (Kerberos). Active Directory speaks
	// only this. It is the default because every deployment that predates the
	// mode switch runs it and sets no RFC2136_AUTH_MODE.
	AuthGSSTSIG AuthMode = "gss-tsig"
	// AuthHMACTSIG is RFC 8945 TSIG with a pre-shared HMAC key — what BIND,
	// Knot, PowerDNS and Technitium speak.
	AuthHMACTSIG AuthMode = "hmac-tsig"
	// AuthInsecure sends unsigned UPDATEs, leaving authorisation entirely to
	// the server's network ACL.
	AuthInsecure AuthMode = "insecure"
)

// tsigAlgs maps the env-facing algorithm name to the FQDN form miekg/dns wants
// in SetTsig. Mirrors upstream external-dns's supported set.
var tsigAlgs = map[string]string{
	"hmac-sha1":   dns.HmacSHA1,
	"hmac-sha224": dns.HmacSHA224,
	"hmac-sha256": dns.HmacSHA256,
	"hmac-sha384": dns.HmacSHA384,
	"hmac-sha512": dns.HmacSHA512,
}

type Config struct {
	Listen string
	// AuthMode decides which fields below are meaningful: Realm/Principal/
	// Keytab/Password for gss-tsig, TSIG* for hmac-tsig, none for insecure.
	// Load rejects cross-mode settings rather than ignoring them.
	AuthMode AuthMode
	// TSIGKeyName is the key name as configured on the DNS server, in FQDN
	// form. Only populated in hmac-tsig mode.
	TSIGKeyName string
	// TSIGSecret is the base64 shared secret paired with TSIGKeyName.
	TSIGSecret string
	// TSIGAlgorithm is the canonical FQDN form (e.g. "hmac-sha256."), already
	// validated against tsigAlgs so dnsop can pass it straight to SetTsig.
	TSIGAlgorithm string
	Realm         string
	Principal     string
	// Keytab is the on-disk path used by `kinit -kt`. Empty when password
	// auth is in effect.
	Keytab string
	// Password is the AD service-account password used for `kinit <principal>`
	// (stdin-piped). Empty when keytab auth is in effect. Exactly one of
	// Keytab / Password is populated by Load.
	Password string
	Krb5Conf string
	DryRun   bool
	// KinitRefreshInterval is the UPPER BOUND on the background TGT refresh
	// cadence, not a fixed period. The refresher derives the actual cadence
	// per-ticket from the lifetime the KDC grants
	// (min(this, 0.5*actual_TGT_lifetime)); this value only caps it. Default
	// 8h — deliberately below the common AD MaxTicketAge of 10h so even if
	// the issued lifetime can't be read, the ceiling alone refreshes in time.
	// Overridable via RFC2136_KINIT_REFRESH_INTERVAL using Go duration syntax
	// (e.g. "8h", "30m", "5s") so tests and ops can shorten it without
	// rebuilding.
	KinitRefreshInterval time.Duration

	// Hosts is the ordered list of DC FQDNs to try (failover walks in
	// the order given). Comes from RFC2136_HOSTS as a comma-separated
	// list. Must be non-empty.
	Hosts []string
	// Port is the UDP/TCP port DNS speaks on (default 53).
	Port int
	// Zones is the set of zones this sidecar is authoritative for, in
	// canonical "no trailing dot, lower-case" form. Used both for AXFR
	// targets and for longest-suffix routing of incoming Endpoints to
	// a zone.
	Zones []string
	// AxfrEnabled controls whether GET /records returns the cached AXFR
	// view or an empty list (treating the upstream as a "blind" provider
	// that relies on UPDATE prerequisites for collision detection).
	AxfrEnabled bool
	// DefaultTTL applies when an Endpoint comes in without an explicit TTL.
	DefaultTTL int64
	// MinTTL clamps any TTL below it up to this value. Protects against
	// callers asking for unreasonably short TTLs.
	MinTTL int64
	// CircuitBreakerThreshold is how many consecutive failing AXFR cycles
	// open the per-DC circuit. Default 3.
	CircuitBreakerThreshold int
	// DomainFilter is a list of FQDN suffixes; entries that don't match
	// any of them are silently ignored. Empty = no filter.
	DomainFilter []string
	// AxfrTimeout bounds a single AXFR exchange (dial+read).
	AxfrTimeout time.Duration
	// UpdateTimeout bounds a single UPDATE exchange (dial+write+read).
	UpdateTimeout time.Duration
}

// The sidecar is intentionally ownership-agnostic. It does NOT read
// PROJECT_LABEL or INSTANCE_ID — those are operator-side concepts. The
// operator stamps Labels["owner"] on every Endpoint it sends, and the
// sidecar round-trips that value through the ownership-TXT sibling.

func Load() (Config, error) {
	mode, err := parseAuthMode(os.Getenv("RFC2136_AUTH_MODE"))
	if err != nil {
		return Config{}, err
	}
	if err := rejectForeignEnv(mode); err != nil {
		return Config{}, err
	}
	refresh, err := parseDuration("RFC2136_KINIT_REFRESH_INTERVAL", 8*time.Hour)
	if err != nil {
		return Config{}, err
	}
	var keytab, password string
	if mode == AuthGSSTSIG {
		if keytab, password, err = resolveAuth(); err != nil {
			return Config{}, err
		}
	}
	var tsigKey, tsigSecret, tsigAlg string
	if mode == AuthHMACTSIG {
		if tsigKey, tsigSecret, tsigAlg, err = resolveTSIG(); err != nil {
			return Config{}, err
		}
	}
	axfrTimeout, err := parseSeconds("RFC2136_AXFR_TIMEOUT_SECONDS", 30*time.Second)
	if err != nil {
		return Config{}, err
	}
	updateTimeout, err := parseSeconds("RFC2136_UPDATE_TIMEOUT_SECONDS", 15*time.Second)
	if err != nil {
		return Config{}, err
	}
	port, err := parsePositiveInt("RFC2136_PORT", 53)
	if err != nil {
		return Config{}, err
	}
	defaultTTL, err := parsePositiveInt64("RFC2136_DEFAULT_TTL", 3600)
	if err != nil {
		return Config{}, err
	}
	minTTL, err := parsePositiveInt64("RFC2136_MIN_TTL", 60)
	if err != nil {
		return Config{}, err
	}
	threshold, err := parsePositiveInt("RFC2136_CIRCUIT_BREAKER_THRESHOLD", 3)
	if err != nil {
		return Config{}, err
	}
	hosts, err := parseHosts(os.Getenv("RFC2136_HOSTS"), mode)
	if err != nil {
		return Config{}, err
	}
	zones, err := parseZones(os.Getenv("RFC2136_ZONES"))
	if err != nil {
		return Config{}, err
	}
	domainFilter := parseDomainFilter(os.Getenv("RFC2136_DOMAIN_FILTER"))

	principal, err := envOrFile("RFC2136_KERBEROS_PRINCIPAL", "RFC2136_KERBEROS_PRINCIPAL_FILE")
	if err != nil {
		return Config{}, err
	}

	c := Config{
		Listen:                  envOr("WEBHOOK_LISTEN", ":9090"),
		AuthMode:                mode,
		TSIGKeyName:             tsigKey,
		TSIGSecret:              tsigSecret,
		TSIGAlgorithm:           tsigAlg,
		Realm:                   os.Getenv("RFC2136_KERBEROS_REALM"),
		Principal:               principal,
		Keytab:                  keytab,
		Password:                password,
		Krb5Conf:                envOr("RFC2136_KRB5_CONF", "/etc/krb5.conf"),
		DryRun:                  parseBool("RFC2136_DRY_RUN"),
		KinitRefreshInterval:    refresh,
		Hosts:                   hosts,
		Port:                    port,
		Zones:                   zones,
		AxfrEnabled:             parseBoolDefault("RFC2136_AXFR_ENABLED", true),
		DefaultTTL:              defaultTTL,
		MinTTL:                  minTTL,
		CircuitBreakerThreshold: threshold,
		DomainFilter:            domainFilter,
		AxfrTimeout:             axfrTimeout,
		UpdateTimeout:           updateTimeout,
	}
	if err := c.validate(); err != nil {
		return c, err
	}
	return c, nil
}

// validate enforces the per-mode contract for whichever auth mode is active.
func (c Config) validate() error {
	switch c.AuthMode {
	case AuthGSSTSIG:
		if c.Realm == "" {
			return errors.New("RFC2136_KERBEROS_REALM is required in gss-tsig mode")
		}
		if c.Principal == "" {
			return errors.New("RFC2136_KERBEROS_PRINCIPAL is required in gss-tsig mode")
		}
		if c.Keytab == "" && c.Password == "" {
			return errors.New("one of RFC2136_KEYTAB_FILE, RFC2136_KEYTAB_BASE64, RFC2136_KEYTAB_BASE64_FILE, RFC2136_AD_PASSWORD, or RFC2136_AD_PASSWORD_FILE is required in gss-tsig mode")
		}
		if !strings.Contains(c.Principal, "@") {
			return errors.New("RFC2136_KERBEROS_PRINCIPAL must be in name@REALM form")
		}
	case AuthHMACTSIG:
		if c.TSIGKeyName == "" {
			return errors.New("RFC2136_TSIG_KEY_NAME is required in hmac-tsig mode")
		}
		if c.TSIGSecret == "" {
			return errors.New("one of RFC2136_TSIG_SECRET or RFC2136_TSIG_SECRET_FILE is required in hmac-tsig mode")
		}
	case AuthInsecure:
		// Nothing to check: the mode's whole point is that we sign nothing.
		// rejectForeignEnv has already refused any auth settings.
	}
	return nil
}

func parseAuthMode(raw string) (AuthMode, error) {
	switch m := AuthMode(strings.ToLower(strings.TrimSpace(raw))); m {
	case "":
		return AuthGSSTSIG, nil
	case AuthGSSTSIG, AuthHMACTSIG, AuthInsecure:
		return m, nil
	default:
		return "", fmt.Errorf("RFC2136_AUTH_MODE: %q is not one of %s, %s, %s", raw, AuthGSSTSIG, AuthHMACTSIG, AuthInsecure)
	}
}

// Settings that only one mode reads. Anything here being set under a different
// mode is refused rather than ignored: a stray RFC2136_AD_PASSWORD in
// hmac-tsig mode means someone believes they configured auth that is never read.
var (
	gssEnvVars = []string{
		"RFC2136_KERBEROS_REALM", "RFC2136_KERBEROS_PRINCIPAL", "RFC2136_KERBEROS_PRINCIPAL_FILE",
		"RFC2136_KEYTAB_FILE", "RFC2136_KEYTAB_BASE64", "RFC2136_KEYTAB_BASE64_FILE",
		"RFC2136_AD_PASSWORD", "RFC2136_AD_PASSWORD_FILE",
		"RFC2136_KRB5_CONF", "RFC2136_KINIT_REFRESH_INTERVAL",
	}
	tsigEnvVars = []string{
		"RFC2136_TSIG_KEY_NAME", "RFC2136_TSIG_SECRET", "RFC2136_TSIG_SECRET_FILE",
		"RFC2136_TSIG_ALGORITHM",
	}
)

func rejectForeignEnv(mode AuthMode) error {
	foreign := map[AuthMode][][]string{
		AuthGSSTSIG:  {tsigEnvVars},
		AuthHMACTSIG: {gssEnvVars},
		AuthInsecure: {gssEnvVars, tsigEnvVars},
	}
	for _, group := range foreign[mode] {
		for _, k := range group {
			if os.Getenv(k) != "" {
				return fmt.Errorf("%s is set but RFC2136_AUTH_MODE=%s never reads it", k, mode)
			}
		}
	}
	return nil
}

// resolveTSIG reads the hmac-tsig key material. The secret follows the same
// env-or-file pattern as the Kerberos password so it can arrive as a Docker
// secret. Key name and algorithm come back in the FQDN form miekg/dns wants,
// so dnsop can hand them to SetTsig untouched.
func resolveTSIG() (string, string, string, error) {
	secret, err := envOrFile("RFC2136_TSIG_SECRET", "RFC2136_TSIG_SECRET_FILE")
	if err != nil {
		return "", "", "", err
	}
	algName := strings.ToLower(strings.TrimSpace(envOr("RFC2136_TSIG_ALGORITHM", "hmac-sha256")))
	alg, ok := tsigAlgs[algName]
	if !ok {
		return "", "", "", fmt.Errorf("RFC2136_TSIG_ALGORITHM: %q is not a supported TSIG algorithm (want one of %s)", algName, strings.Join(supportedAlgs(), ", "))
	}
	var name string
	if raw := strings.TrimSpace(os.Getenv("RFC2136_TSIG_KEY_NAME")); raw != "" {
		name = dns.Fqdn(strings.ToLower(raw))
	}
	return name, secret, alg, nil
}

func supportedAlgs() []string {
	out := make([]string, 0, len(tsigAlgs))
	for k := range tsigAlgs {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// resolveAuth picks exactly one of the five secret sources and returns either a
// keytab path or a password string. All sources are mutually exclusive; any
// combination is rejected at startup so misconfiguration fails fast rather
// than silently picking one and ignoring the others.
//
//  1. RFC2136_KEYTAB_FILE        — keytab mounted at a path (Docker secret / volume)
//  2. RFC2136_KEYTAB_BASE64      — keytab as base64-encoded bytes (env-only stores)
//  3. RFC2136_KEYTAB_BASE64_FILE — base64-encoded keytab read from a file
//     (Docker secret holding the base64 string)
//  4. RFC2136_AD_PASSWORD        — service-account password as env string
//  5. RFC2136_AD_PASSWORD_FILE   — password from a file (Docker secret)
//
// Returns (keytabPath, password, error). Exactly one of keytabPath / password
// is non-empty on success.
func resolveAuth() (string, string, error) {
	keytabFile := os.Getenv("RFC2136_KEYTAB_FILE")
	keytabB64 := os.Getenv("RFC2136_KEYTAB_BASE64")
	keytabB64File := os.Getenv("RFC2136_KEYTAB_BASE64_FILE")
	password := os.Getenv("RFC2136_AD_PASSWORD")
	passwordFile := os.Getenv("RFC2136_AD_PASSWORD_FILE")

	sources := 0
	for _, v := range []string{keytabFile, keytabB64, keytabB64File, password, passwordFile} {
		if v != "" {
			sources++
		}
	}
	if sources > 1 {
		return "", "", errors.New("set exactly one of RFC2136_KEYTAB_FILE, RFC2136_KEYTAB_BASE64, RFC2136_KEYTAB_BASE64_FILE, RFC2136_AD_PASSWORD, RFC2136_AD_PASSWORD_FILE")
	}

	if keytabFile != "" {
		return keytabFile, "", nil
	}
	if keytabB64 != "" {
		path, err := materialiseKeytabFromBase64(keytabB64)
		return path, "", err
	}
	if keytabB64File != "" {
		b, err := os.ReadFile(keytabB64File)
		if err != nil {
			return "", "", fmt.Errorf("RFC2136_KEYTAB_BASE64_FILE: read: %w", err)
		}
		path, err := materialiseKeytabFromBase64(string(b))
		return path, "", err
	}
	if password != "" {
		return "", password, nil
	}
	if passwordFile != "" {
		b, err := os.ReadFile(passwordFile)
		if err != nil {
			return "", "", fmt.Errorf("RFC2136_AD_PASSWORD_FILE: read: %w", err)
		}
		return "", strings.TrimRight(string(b), "\r\n"), nil
	}
	return "", "", nil
}

// envOrFile resolves a string value from either an env var or a file path env
// var (mutually exclusive). Used for non-secret-but-sensitive identifiers
// (e.g. Kerberos principal) that operators may want delivered via Docker
// secret rather than as a service-inspect-visible env var.
func envOrFile(envKey, fileKey string) (string, error) {
	env := os.Getenv(envKey)
	file := os.Getenv(fileKey)
	switch {
	case env != "" && file != "":
		return "", fmt.Errorf("set exactly one of %s or %s", envKey, fileKey)
	case env != "":
		return env, nil
	case file != "":
		b, err := os.ReadFile(file)
		if err != nil {
			return "", fmt.Errorf("%s: read: %w", fileKey, err)
		}
		return strings.TrimRight(string(b), "\r\n"), nil
	}
	return "", nil
}

func materialiseKeytabFromBase64(b64 string) (string, error) {
	data, err := base64.StdEncoding.DecodeString(strings.TrimSpace(b64))
	if err != nil {
		return "", fmt.Errorf("RFC2136_KEYTAB_BASE64: decode: %w", err)
	}
	f, err := os.CreateTemp("", "ddo-keytab-*")
	if err != nil {
		return "", fmt.Errorf("RFC2136_KEYTAB_BASE64: create temp: %w", err)
	}
	defer f.Close()
	if err := os.Chmod(f.Name(), 0o600); err != nil {
		return "", fmt.Errorf("RFC2136_KEYTAB_BASE64: chmod: %w", err)
	}
	if _, err := f.Write(data); err != nil {
		return "", fmt.Errorf("RFC2136_KEYTAB_BASE64: write: %w", err)
	}
	return f.Name(), nil
}

func envOr(key, fallback string) string {
	if v, ok := os.LookupEnv(key); ok && v != "" {
		return v
	}
	return fallback
}

func parseBool(key string) bool {
	v := os.Getenv(key)
	if v == "" {
		return false
	}
	b, _ := strconv.ParseBool(v)
	return b
}

// parseBoolDefault mirrors parseBool but takes a non-false default for env
// vars whose absence should mean "on" (e.g. RFC2136_AXFR_ENABLED).
func parseBoolDefault(key string, fallback bool) bool {
	v := os.Getenv(key)
	if v == "" {
		return fallback
	}
	b, err := strconv.ParseBool(v)
	if err != nil {
		return fallback
	}
	return b
}

func parseDuration(key string, fallback time.Duration) (time.Duration, error) {
	v := os.Getenv(key)
	if v == "" {
		return fallback, nil
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		return 0, fmt.Errorf("%s: invalid duration %q: %w", key, v, err)
	}
	if d <= 0 {
		return 0, fmt.Errorf("%s: must be > 0, got %v", key, d)
	}
	return d, nil
}

func parseSeconds(key string, fallback time.Duration) (time.Duration, error) {
	v := os.Getenv(key)
	if v == "" {
		return fallback, nil
	}
	n, err := strconv.Atoi(v)
	if err != nil || n <= 0 {
		return 0, fmt.Errorf("%s: must be a positive integer (seconds), got %q", key, v)
	}
	return time.Duration(n) * time.Second, nil
}

func parsePositiveInt(key string, fallback int) (int, error) {
	v := os.Getenv(key)
	if v == "" {
		return fallback, nil
	}
	n, err := strconv.Atoi(v)
	if err != nil || n <= 0 {
		return 0, fmt.Errorf("%s: must be a positive integer, got %q", key, v)
	}
	return n, nil
}

func parsePositiveInt64(key string, fallback int64) (int64, error) {
	v := os.Getenv(key)
	if v == "" {
		return fallback, nil
	}
	n, err := strconv.ParseInt(v, 10, 64)
	if err != nil || n <= 0 {
		return 0, fmt.Errorf("%s: must be a positive integer, got %q", key, v)
	}
	return n, nil
}

// fqdnRe matches a simple multi-label hostname. It deliberately rejects bare
// names ("dc01") and IP literals — DNS-over-Kerberos can only target an
// FQDN whose SPN exists in AD, so accepting an IP there would mask a real
// misconfiguration. Plain TSIG has no such constraint: it signs with a
// pre-shared key and never resolves an SPN, so a BIND or Technitium box
// reached at 10.1.125.10 is perfectly legitimate.
var fqdnRe = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+\.?$`)

func parseHosts(raw string, mode AuthMode) ([]string, error) {
	if raw == "" {
		return nil, errors.New("RFC2136_HOSTS is required (comma-separated server names)")
	}
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		h := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(p)), ".")
		if h == "" {
			continue
		}
		if ip := net.ParseIP(h); ip != nil {
			if mode == AuthGSSTSIG {
				return nil, fmt.Errorf("RFC2136_HOSTS: %q is an IP literal — Kerberos auth requires an FQDN with a matching SPN", h)
			}
			out = append(out, h)
			continue
		}
		if !fqdnRe.MatchString(h) {
			return nil, fmt.Errorf("RFC2136_HOSTS: %q is not a valid FQDN", h)
		}
		out = append(out, h)
	}
	if len(out) == 0 {
		return nil, errors.New("RFC2136_HOSTS is required (comma-separated server names)")
	}
	return out, nil
}

func parseZones(raw string) ([]string, error) {
	if raw == "" {
		return nil, errors.New("RFC2136_ZONES is required (comma-separated zone names)")
	}
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		z := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(p)), ".")
		if z == "" {
			continue
		}
		// A bare label like "corp" with no dot is rejected — every real
		// AD-integrated zone we care about is at least two labels.
		if !strings.Contains(z, ".") {
			return nil, fmt.Errorf("RFC2136_ZONES: %q must be a multi-label zone (e.g. corp.example.com)", z)
		}
		out = append(out, z)
	}
	if len(out) == 0 {
		return nil, errors.New("RFC2136_ZONES is required (comma-separated zone names)")
	}
	return out, nil
}

func parseDomainFilter(raw string) []string {
	if raw == "" {
		return nil
	}
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		s := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(p)), ".")
		if s == "" {
			continue
		}
		out = append(out, s)
	}
	return out
}
