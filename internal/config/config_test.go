package config

import (
	"bytes"
	"encoding/base64"
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

func TestLoad_Base64KeytabMaterialisesToTempFile(t *testing.T) {
	os.Clearenv()
	want := []byte{0x05, 0x02, 0xde, 0xad, 0xbe, 0xef}
	t.Setenv("RFC2136_KERBEROS_REALM", "CORP.EXAMPLE.COM")
	t.Setenv("RFC2136_KERBEROS_PRINCIPAL", "svc-dns@CORP.EXAMPLE.COM")
	t.Setenv("RFC2136_KEYTAB_BASE64", base64.StdEncoding.EncodeToString(want))
	cfg, err := Load()
	if err != nil {
		t.Fatalf("unexpected: %v", err)
	}
	if cfg.Keytab == "" {
		t.Fatalf("Keytab path empty")
	}
	t.Cleanup(func() { _ = os.Remove(cfg.Keytab) })

	got, err := os.ReadFile(cfg.Keytab)
	if err != nil {
		t.Fatalf("read materialised keytab: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("materialised bytes mismatch: got %x want %x", got, want)
	}
	info, err := os.Stat(cfg.Keytab)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Fatalf("keytab perms got %o want 0600", perm)
	}
}

func TestLoad_Base64KeytabTrimsWhitespace(t *testing.T) {
	os.Clearenv()
	want := []byte("not-a-real-keytab-but-decoded-cleanly")
	encoded := base64.StdEncoding.EncodeToString(want)
	t.Setenv("RFC2136_KERBEROS_REALM", "CORP.EXAMPLE.COM")
	t.Setenv("RFC2136_KERBEROS_PRINCIPAL", "svc-dns@CORP.EXAMPLE.COM")
	t.Setenv("RFC2136_KEYTAB_BASE64", "\n  "+encoded+"  \n")
	cfg, err := Load()
	if err != nil {
		t.Fatalf("unexpected: %v", err)
	}
	t.Cleanup(func() { _ = os.Remove(cfg.Keytab) })
	got, _ := os.ReadFile(cfg.Keytab)
	if !bytes.Equal(got, want) {
		t.Fatalf("trimmed decode mismatch")
	}
}

func TestLoad_Base64KeytabInvalidBase64Errors(t *testing.T) {
	os.Clearenv()
	t.Setenv("RFC2136_KERBEROS_REALM", "CORP.EXAMPLE.COM")
	t.Setenv("RFC2136_KERBEROS_PRINCIPAL", "svc-dns@CORP.EXAMPLE.COM")
	t.Setenv("RFC2136_KEYTAB_BASE64", "***not-base64***")
	if _, err := Load(); err == nil {
		t.Fatalf("expected decode error")
	}
}

func TestLoad_BothKeytabSourcesRejected(t *testing.T) {
	os.Clearenv()
	t.Setenv("RFC2136_KERBEROS_REALM", "CORP.EXAMPLE.COM")
	t.Setenv("RFC2136_KERBEROS_PRINCIPAL", "svc-dns@CORP.EXAMPLE.COM")
	t.Setenv("RFC2136_KEYTAB_FILE", "/run/secrets/keytab")
	t.Setenv("RFC2136_KEYTAB_BASE64", base64.StdEncoding.EncodeToString([]byte("xyz")))
	if _, err := Load(); err == nil {
		t.Fatalf("expected mutual-exclusion error")
	}
}

func TestLoad_NoKeytabSourceErrors(t *testing.T) {
	os.Clearenv()
	t.Setenv("RFC2136_KERBEROS_REALM", "CORP.EXAMPLE.COM")
	t.Setenv("RFC2136_KERBEROS_PRINCIPAL", "svc-dns@CORP.EXAMPLE.COM")
	if _, err := Load(); err == nil {
		t.Fatalf("expected error when no auth source set")
	}
}

func TestLoad_PasswordFromEnv(t *testing.T) {
	os.Clearenv()
	t.Setenv("RFC2136_KERBEROS_REALM", "CORP.EXAMPLE.COM")
	t.Setenv("RFC2136_KERBEROS_PRINCIPAL", "svc-dns@CORP.EXAMPLE.COM")
	t.Setenv("RFC2136_AD_PASSWORD", "hunter2")
	cfg, err := Load()
	if err != nil {
		t.Fatalf("unexpected: %v", err)
	}
	if cfg.Password != "hunter2" {
		t.Fatalf("password not captured: %q", cfg.Password)
	}
	if cfg.Keytab != "" {
		t.Fatalf("keytab must remain empty in password mode, got %q", cfg.Keytab)
	}
}

func TestLoad_PasswordFromFile(t *testing.T) {
	os.Clearenv()
	dir := t.TempDir()
	pwPath := dir + "/pw"
	if err := os.WriteFile(pwPath, []byte("hunter2\n"), 0o600); err != nil {
		t.Fatalf("setup: %v", err)
	}
	t.Setenv("RFC2136_KERBEROS_REALM", "CORP.EXAMPLE.COM")
	t.Setenv("RFC2136_KERBEROS_PRINCIPAL", "svc-dns@CORP.EXAMPLE.COM")
	t.Setenv("RFC2136_AD_PASSWORD_FILE", pwPath)
	cfg, err := Load()
	if err != nil {
		t.Fatalf("unexpected: %v", err)
	}
	if cfg.Password != "hunter2" {
		t.Fatalf("password from file: got %q want %q (trailing newline must be stripped)", cfg.Password, "hunter2")
	}
}

func TestLoad_PasswordFromMissingFile(t *testing.T) {
	os.Clearenv()
	t.Setenv("RFC2136_KERBEROS_REALM", "CORP.EXAMPLE.COM")
	t.Setenv("RFC2136_KERBEROS_PRINCIPAL", "svc-dns@CORP.EXAMPLE.COM")
	t.Setenv("RFC2136_AD_PASSWORD_FILE", "/nonexistent/path/to/file")
	if _, err := Load(); err == nil {
		t.Fatalf("expected error when password file missing")
	}
}

func TestLoad_MultipleAuthSourcesRejected(t *testing.T) {
	cases := []struct {
		name string
		env  map[string]string
	}{
		{"file+base64", map[string]string{
			"RFC2136_KEYTAB_FILE":   "/run/secrets/keytab",
			"RFC2136_KEYTAB_BASE64": base64.StdEncoding.EncodeToString([]byte("x")),
		}},
		{"file+password", map[string]string{
			"RFC2136_KEYTAB_FILE": "/run/secrets/keytab",
			"RFC2136_AD_PASSWORD": "hunter2",
		}},
		{"base64+password", map[string]string{
			"RFC2136_KEYTAB_BASE64": base64.StdEncoding.EncodeToString([]byte("x")),
			"RFC2136_AD_PASSWORD":   "hunter2",
		}},
		{"password+passwordfile", map[string]string{
			"RFC2136_AD_PASSWORD":      "hunter2",
			"RFC2136_AD_PASSWORD_FILE": "/tmp/pw",
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			os.Clearenv()
			t.Setenv("RFC2136_KERBEROS_REALM", "CORP.EXAMPLE.COM")
			t.Setenv("RFC2136_KERBEROS_PRINCIPAL", "svc-dns@CORP.EXAMPLE.COM")
			for k, v := range tc.env {
				t.Setenv(k, v)
			}
			if _, err := Load(); err == nil {
				t.Fatalf("expected mutual-exclusion error")
			}
		})
	}
}
