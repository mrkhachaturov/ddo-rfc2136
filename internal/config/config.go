package config

import (
	"encoding/base64"
	"errors"
	"fmt"
	"os"
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
	c := Config{
		Listen:               envOr("WEBHOOK_LISTEN", ":9090"),
		Realm:                os.Getenv("RFC2136_KERBEROS_REALM"),
		Principal:            os.Getenv("RFC2136_KERBEROS_PRINCIPAL"),
		Keytab:               keytab,
		Password:             password,
		Krb5Conf:             envOr("RFC2136_KRB5_CONF", "/etc/krb5.conf"),
		DryRun:               parseBool("RFC2136_DRY_RUN"),
		KinitRefreshInterval: refresh,
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
