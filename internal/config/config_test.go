package config

import (
	"os"
	"testing"
	"time"
)

func TestLoad_HappyPath(t *testing.T) {
	t.Setenv("WEBHOOK_LISTEN", ":9090")
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

func TestLoad_KinitRefreshIntervalDefaultIs12h(t *testing.T) {
	os.Clearenv()
	t.Setenv("RFC2136_KERBEROS_REALM", "CORP.EXAMPLE.COM")
	t.Setenv("RFC2136_KERBEROS_PRINCIPAL", "svc-dns@CORP.EXAMPLE.COM")
	t.Setenv("RFC2136_KEYTAB_FILE", "/run/secrets/keytab")
	cfg, err := Load()
	if err != nil {
		t.Fatalf("unexpected: %v", err)
	}
	if cfg.KinitRefreshInterval != 12*time.Hour {
		t.Fatalf("default KinitRefreshInterval: got %v want %v", cfg.KinitRefreshInterval, 12*time.Hour)
	}
}

func TestLoad_KinitRefreshIntervalOverride(t *testing.T) {
	os.Clearenv()
	t.Setenv("RFC2136_KERBEROS_REALM", "CORP.EXAMPLE.COM")
	t.Setenv("RFC2136_KERBEROS_PRINCIPAL", "svc-dns@CORP.EXAMPLE.COM")
	t.Setenv("RFC2136_KEYTAB_FILE", "/run/secrets/keytab")
	t.Setenv("RFC2136_KINIT_REFRESH_INTERVAL", "500ms")
	cfg, err := Load()
	if err != nil {
		t.Fatalf("unexpected: %v", err)
	}
	if cfg.KinitRefreshInterval != 500*time.Millisecond {
		t.Fatalf("KinitRefreshInterval: got %v want 500ms", cfg.KinitRefreshInterval)
	}
}

func TestLoad_KinitRefreshIntervalInvalid(t *testing.T) {
	os.Clearenv()
	t.Setenv("RFC2136_KERBEROS_REALM", "CORP.EXAMPLE.COM")
	t.Setenv("RFC2136_KERBEROS_PRINCIPAL", "svc-dns@CORP.EXAMPLE.COM")
	t.Setenv("RFC2136_KEYTAB_FILE", "/run/secrets/keytab")
	t.Setenv("RFC2136_KINIT_REFRESH_INTERVAL", "not-a-duration")
	_, err := Load()
	if err == nil {
		t.Fatalf("expected error on invalid duration")
	}
}
