package config

import (
	"os"
	"testing"
)

func TestLoad_HappyPath(t *testing.T) {
	t.Setenv("TRANSPORT_LISTEN", ":9090")
	t.Setenv("RFC2136_KERBEROS_REALM", "CORP.EXAMPLE.COM")
	t.Setenv("RFC2136_KERBEROS_PRINCIPAL", "svc-dns@CORP.EXAMPLE.COM")
	t.Setenv("RFC2136_KEYTAB_FILE", "/run/secrets/keytab")
	cfg, err := Load()
	if err != nil {
		t.Fatalf("unexpected: %v", err)
	}
	if cfg.Listen != ":9090" || cfg.Principal != "svc-dns@CORP.EXAMPLE.COM" {
		t.Fatalf("bad parse: %+v", cfg)
	}
	if cfg.Krb5Conf != "/etc/krb5.conf" {
		t.Fatalf("default not applied: %s", cfg.Krb5Conf)
	}
}

func TestLoad_MissingKeytab(t *testing.T) {
	os.Clearenv()
	t.Setenv("RFC2136_KERBEROS_REALM", "CORP.EXAMPLE.COM")
	t.Setenv("RFC2136_KERBEROS_PRINCIPAL", "svc-dns@CORP.EXAMPLE.COM")
	_, err := Load()
	if err == nil {
		t.Fatalf("expected error on missing RFC2136_KEYTAB_FILE")
	}
}

func TestLoad_DryRunFlag(t *testing.T) {
	t.Setenv("RFC2136_KERBEROS_REALM", "CORP.EXAMPLE.COM")
	t.Setenv("RFC2136_KERBEROS_PRINCIPAL", "svc-dns@CORP.EXAMPLE.COM")
	t.Setenv("RFC2136_KEYTAB_FILE", "/run/secrets/keytab")
	t.Setenv("RFC2136_DRY_RUN", "true")
	cfg, _ := Load()
	if !cfg.DryRun {
		t.Fatalf("expected DryRun=true")
	}
}
