package config

import (
	"errors"
	"os"
	"strconv"
	"strings"
)

type Config struct {
	Listen    string
	Realm     string
	Principal string
	Keytab    string
	Krb5Conf  string
	DryRun    bool
}

func Load() (Config, error) {
	c := Config{
		Listen:    envOr("TRANSPORT_LISTEN", ":9090"),
		Realm:     os.Getenv("RFC2136_KERBEROS_REALM"),
		Principal: os.Getenv("RFC2136_KERBEROS_PRINCIPAL"),
		Keytab:    os.Getenv("RFC2136_KEYTAB_FILE"),
		Krb5Conf:  envOr("RFC2136_KRB5_CONF", "/etc/krb5.conf"),
		DryRun:    parseBool("RFC2136_DRY_RUN"),
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
