package config

import (
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	Listen    string
	Realm     string
	Principal string
	// Keytab is the on-disk path used by `kinit -kt`. Empty when password
	// auth is in effect.
	Keytab string
	// Password is the AD service-account password used for `kinit <principal>`
	// (stdin-piped). Empty when keytab auth is in effect. Exactly one of
	// Keytab / Password is populated by Load.
	Password string
	Krb5Conf string
	DryRun   bool
	// KinitRefreshInterval controls how often the background goroutine
	// re-runs kinit to keep the TGT fresh. Default 12h (half of the AD
	// default ticket lifetime). Overridable via RFC2136_KINIT_REFRESH_INTERVAL
	// using Go duration syntax (e.g. "12h", "30m", "5s") so tests and ops
	// can shorten it without rebuilding.
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
	// OwnershipLabel is "<PROJECT_LABEL>:<INSTANCE_ID>" — the value the
	// ownership-TXT records carry. Reads default to "docker-dns-operator:1".
	OwnershipLabel string
}

func Load() (Config, error) {
	refresh, err := parseDuration("RFC2136_KINIT_REFRESH_INTERVAL", 12*time.Hour)
	if err != nil {
		return Config{}, err
	}
	keytab, password, err := resolveAuth()
	if err != nil {
		return Config{}, err
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
	hosts, err := parseHosts(os.Getenv("RFC2136_HOSTS"))
	if err != nil {
		return Config{}, err
	}
	zones, err := parseZones(os.Getenv("RFC2136_ZONES"))
	if err != nil {
		return Config{}, err
	}
	domainFilter := parseDomainFilter(os.Getenv("RFC2136_DOMAIN_FILTER"))

	projectLabel := envOr("PROJECT_LABEL", "docker-dns-operator")
	instanceID := envOr("INSTANCE_ID", "1")

	c := Config{
		Listen:                  envOr("WEBHOOK_LISTEN", ":9090"),
		Realm:                   os.Getenv("RFC2136_KERBEROS_REALM"),
		Principal:               os.Getenv("RFC2136_KERBEROS_PRINCIPAL"),
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
		OwnershipLabel:          projectLabel + ":" + instanceID,
	}
	if c.Realm == "" {
		return c, errors.New("RFC2136_KERBEROS_REALM is required")
	}
	if c.Principal == "" {
		return c, errors.New("RFC2136_KERBEROS_PRINCIPAL is required")
	}
	if c.Keytab == "" && c.Password == "" {
		return c, errors.New("one of RFC2136_KEYTAB_FILE, RFC2136_KEYTAB_BASE64, RFC2136_AD_PASSWORD, or RFC2136_AD_PASSWORD_FILE is required")
	}
	if !strings.Contains(c.Principal, "@") {
		return c, errors.New("RFC2136_KERBEROS_PRINCIPAL must be in name@REALM form")
	}
	return c, nil
}

// resolveAuth picks exactly one of the four secret sources and returns either a
// keytab path or a password string. The four sources are mutually exclusive;
// any combination is rejected at startup so misconfiguration fails fast rather
// than silently picking one and ignoring the others.
//
//  1. RFC2136_KEYTAB_FILE   — keytab mounted at a path (Docker secret / volume)
//  2. RFC2136_KEYTAB_BASE64 — keytab as base64-encoded bytes (env-only stores)
//  3. RFC2136_AD_PASSWORD   — service-account password as env string
//  4. RFC2136_AD_PASSWORD_FILE — password from a file (Docker secret)
//
// Returns (keytabPath, password, error). Exactly one of keytabPath / password
// is non-empty on success.
func resolveAuth() (string, string, error) {
	keytabFile := os.Getenv("RFC2136_KEYTAB_FILE")
	keytabB64 := os.Getenv("RFC2136_KEYTAB_BASE64")
	password := os.Getenv("RFC2136_AD_PASSWORD")
	passwordFile := os.Getenv("RFC2136_AD_PASSWORD_FILE")

	sources := 0
	for _, v := range []string{keytabFile, keytabB64, password, passwordFile} {
		if v != "" {
			sources++
		}
	}
	if sources > 1 {
		return "", "", errors.New("set exactly one of RFC2136_KEYTAB_FILE, RFC2136_KEYTAB_BASE64, RFC2136_AD_PASSWORD, RFC2136_AD_PASSWORD_FILE")
	}

	if keytabFile != "" {
		return keytabFile, "", nil
	}
	if keytabB64 != "" {
		path, err := materialiseKeytabFromBase64(keytabB64)
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
// FQDN whose SPN exists in AD, so accepting an IP here would mask a real
// misconfiguration.
var fqdnRe = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+\.?$`)

func parseHosts(raw string) ([]string, error) {
	if raw == "" {
		return nil, errors.New("RFC2136_HOSTS is required (comma-separated DC FQDNs)")
	}
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		h := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(p)), ".")
		if h == "" {
			continue
		}
		if ip := net.ParseIP(h); ip != nil {
			return nil, fmt.Errorf("RFC2136_HOSTS: %q is an IP literal — Kerberos auth requires an FQDN with a matching SPN", h)
		}
		if !fqdnRe.MatchString(h) {
			return nil, fmt.Errorf("RFC2136_HOSTS: %q is not a valid FQDN", h)
		}
		out = append(out, h)
	}
	if len(out) == 0 {
		return nil, errors.New("RFC2136_HOSTS is required (comma-separated DC FQDNs)")
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
