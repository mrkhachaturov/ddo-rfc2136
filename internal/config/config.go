package config

import (
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
	Keytab    string
	Krb5Conf  string
	DryRun    bool
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
	c := Config{
		Listen:               envOr("TRANSPORT_LISTEN", ":9090"),
		Realm:                os.Getenv("RFC2136_KERBEROS_REALM"),
		Principal:            os.Getenv("RFC2136_KERBEROS_PRINCIPAL"),
		Keytab:               os.Getenv("RFC2136_KEYTAB_FILE"),
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
	if c.Keytab == "" {
		return c, errors.New("RFC2136_KEYTAB_FILE is required")
	}
	if !strings.Contains(c.Principal, "@") {
		return c, errors.New("RFC2136_KERBEROS_PRINCIPAL must be in name@REALM form")
	}
	return c, nil
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
