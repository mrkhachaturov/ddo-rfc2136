package config

import (
	"bytes"
	"encoding/base64"
	"os"
	"testing"
	"time"
)

func TestLoad_HappyPath(t *testing.T) {
	withRequiredEnv(t)
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

// withRequiredEnv sets the minimum env required by Load so individual tests
// can focus on the variable they exercise. Tests that explicitly want a clean
// env should call os.Clearenv() before invoking this helper.
func withRequiredEnv(t *testing.T) {
	t.Helper()
	t.Setenv("WEBHOOK_LISTEN", ":9090")
	t.Setenv("RFC2136_KERBEROS_REALM", "CORP.EXAMPLE.COM")
	t.Setenv("RFC2136_KERBEROS_PRINCIPAL", "svc-dns@CORP.EXAMPLE.COM")
	t.Setenv("RFC2136_KEYTAB_FILE", "/run/secrets/keytab")
	t.Setenv("RFC2136_HOSTS", "dc01.corp.example.com,dc02.corp.example.com")
	t.Setenv("RFC2136_ZONES", "corp.example.com")
}

func TestLoad_MissingKeytab(t *testing.T) {
	os.Clearenv()
	t.Setenv("RFC2136_KERBEROS_REALM", "CORP.EXAMPLE.COM")
	t.Setenv("RFC2136_KERBEROS_PRINCIPAL", "svc-dns@CORP.EXAMPLE.COM")
	t.Setenv("RFC2136_HOSTS", "dc01.corp.example.com")
	t.Setenv("RFC2136_ZONES", "corp.example.com")
	_, err := Load()
	if err == nil {
		t.Fatalf("expected error on missing RFC2136_KEYTAB_FILE")
	}
}

func TestLoad_DryRunFlag(t *testing.T) {
	withRequiredEnv(t)
	t.Setenv("RFC2136_DRY_RUN", "true")
	cfg, _ := Load()
	if !cfg.DryRun {
		t.Fatalf("expected DryRun=true")
	}
}

func TestLoad_KinitRefreshIntervalDefaultIs12h(t *testing.T) {
	os.Clearenv()
	withRequiredEnv(t)
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
	withRequiredEnv(t)
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
	withRequiredEnv(t)
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
	t.Setenv("RFC2136_HOSTS", "dc01.corp.example.com")
	t.Setenv("RFC2136_ZONES", "corp.example.com")
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
	t.Setenv("RFC2136_HOSTS", "dc01.corp.example.com")
	t.Setenv("RFC2136_ZONES", "corp.example.com")
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
	t.Setenv("RFC2136_HOSTS", "dc01.corp.example.com")
	t.Setenv("RFC2136_ZONES", "corp.example.com")
	t.Setenv("RFC2136_KEYTAB_BASE64", "***not-base64***")
	if _, err := Load(); err == nil {
		t.Fatalf("expected decode error")
	}
}

func TestLoad_BothKeytabSourcesRejected(t *testing.T) {
	os.Clearenv()
	t.Setenv("RFC2136_KERBEROS_REALM", "CORP.EXAMPLE.COM")
	t.Setenv("RFC2136_KERBEROS_PRINCIPAL", "svc-dns@CORP.EXAMPLE.COM")
	t.Setenv("RFC2136_HOSTS", "dc01.corp.example.com")
	t.Setenv("RFC2136_ZONES", "corp.example.com")
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
	t.Setenv("RFC2136_HOSTS", "dc01.corp.example.com")
	t.Setenv("RFC2136_ZONES", "corp.example.com")
	if _, err := Load(); err == nil {
		t.Fatalf("expected error when no auth source set")
	}
}

func TestLoad_PasswordFromEnv(t *testing.T) {
	os.Clearenv()
	t.Setenv("RFC2136_KERBEROS_REALM", "CORP.EXAMPLE.COM")
	t.Setenv("RFC2136_KERBEROS_PRINCIPAL", "svc-dns@CORP.EXAMPLE.COM")
	t.Setenv("RFC2136_HOSTS", "dc01.corp.example.com")
	t.Setenv("RFC2136_ZONES", "corp.example.com")
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
	t.Setenv("RFC2136_HOSTS", "dc01.corp.example.com")
	t.Setenv("RFC2136_ZONES", "corp.example.com")
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
	t.Setenv("RFC2136_HOSTS", "dc01.corp.example.com")
	t.Setenv("RFC2136_ZONES", "corp.example.com")
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
			t.Setenv("RFC2136_HOSTS", "dc01.corp.example.com")
			t.Setenv("RFC2136_ZONES", "corp.example.com")
			for k, v := range tc.env {
				t.Setenv(k, v)
			}
			if _, err := Load(); err == nil {
				t.Fatalf("expected mutual-exclusion error")
			}
		})
	}
}

func TestLoad_HostsAndZonesParsed(t *testing.T) {
	os.Clearenv()
	withRequiredEnv(t)
	t.Setenv("RFC2136_HOSTS", " DC01.corp.example.com , dc02.corp.example.com. ")
	t.Setenv("RFC2136_ZONES", "Corp.Example.COM., other.example.com")
	cfg, err := Load()
	if err != nil {
		t.Fatalf("unexpected: %v", err)
	}
	if len(cfg.Hosts) != 2 || cfg.Hosts[0] != "dc01.corp.example.com" || cfg.Hosts[1] != "dc02.corp.example.com" {
		t.Fatalf("hosts: %+v", cfg.Hosts)
	}
	if len(cfg.Zones) != 2 || cfg.Zones[0] != "corp.example.com" || cfg.Zones[1] != "other.example.com" {
		t.Fatalf("zones: %+v", cfg.Zones)
	}
}

func TestLoad_HostsRejectsIPLiteral(t *testing.T) {
	os.Clearenv()
	withRequiredEnv(t)
	t.Setenv("RFC2136_HOSTS", "10.1.2.3")
	if _, err := Load(); err == nil {
		t.Fatalf("expected error rejecting IP literal in RFC2136_HOSTS")
	}
}

func TestLoad_HostsRejectsBareLabel(t *testing.T) {
	os.Clearenv()
	withRequiredEnv(t)
	t.Setenv("RFC2136_HOSTS", "dc01")
	if _, err := Load(); err == nil {
		t.Fatalf("expected error rejecting bare label in RFC2136_HOSTS")
	}
}

func TestLoad_ZonesRequiresMultiLabel(t *testing.T) {
	os.Clearenv()
	withRequiredEnv(t)
	t.Setenv("RFC2136_ZONES", "corp")
	if _, err := Load(); err == nil {
		t.Fatalf("expected error on single-label zone")
	}
}

func TestLoad_DomainFilterParsed(t *testing.T) {
	os.Clearenv()
	withRequiredEnv(t)
	t.Setenv("RFC2136_DOMAIN_FILTER", "Corp.Example.COM.,svc.example.com")
	cfg, err := Load()
	if err != nil {
		t.Fatalf("unexpected: %v", err)
	}
	if len(cfg.DomainFilter) != 2 || cfg.DomainFilter[0] != "corp.example.com" || cfg.DomainFilter[1] != "svc.example.com" {
		t.Fatalf("DomainFilter: %+v", cfg.DomainFilter)
	}
}

func TestLoad_DomainFilterEmptyByDefault(t *testing.T) {
	os.Clearenv()
	withRequiredEnv(t)
	cfg, err := Load()
	if err != nil {
		t.Fatalf("unexpected: %v", err)
	}
	if len(cfg.DomainFilter) != 0 {
		t.Fatalf("expected empty domain filter, got %+v", cfg.DomainFilter)
	}
}

func TestLoad_AxfrEnabledDefaultTrue(t *testing.T) {
	os.Clearenv()
	withRequiredEnv(t)
	cfg, err := Load()
	if err != nil {
		t.Fatalf("unexpected: %v", err)
	}
	if !cfg.AxfrEnabled {
		t.Fatalf("AxfrEnabled should default to true")
	}
}

func TestLoad_AxfrEnabledDisabled(t *testing.T) {
	os.Clearenv()
	withRequiredEnv(t)
	t.Setenv("RFC2136_AXFR_ENABLED", "false")
	cfg, err := Load()
	if err != nil {
		t.Fatalf("unexpected: %v", err)
	}
	if cfg.AxfrEnabled {
		t.Fatalf("AxfrEnabled should be false")
	}
}

func TestLoad_TTLsAndTimeouts(t *testing.T) {
	os.Clearenv()
	withRequiredEnv(t)
	t.Setenv("RFC2136_DEFAULT_TTL", "1800")
	t.Setenv("RFC2136_MIN_TTL", "120")
	t.Setenv("RFC2136_AXFR_TIMEOUT_SECONDS", "10")
	t.Setenv("RFC2136_UPDATE_TIMEOUT_SECONDS", "5")
	t.Setenv("RFC2136_CIRCUIT_BREAKER_THRESHOLD", "7")
	t.Setenv("RFC2136_PORT", "5353")
	cfg, err := Load()
	if err != nil {
		t.Fatalf("unexpected: %v", err)
	}
	if cfg.DefaultTTL != 1800 || cfg.MinTTL != 120 {
		t.Fatalf("ttl: %+v", cfg)
	}
	if cfg.AxfrTimeout != 10*time.Second || cfg.UpdateTimeout != 5*time.Second {
		t.Fatalf("timeouts: %+v", cfg)
	}
	if cfg.CircuitBreakerThreshold != 7 {
		t.Fatalf("threshold: %d", cfg.CircuitBreakerThreshold)
	}
	if cfg.Port != 5353 {
		t.Fatalf("port: %d", cfg.Port)
	}
}

func TestLoad_TTLDefaults(t *testing.T) {
	os.Clearenv()
	withRequiredEnv(t)
	cfg, err := Load()
	if err != nil {
		t.Fatalf("unexpected: %v", err)
	}
	if cfg.DefaultTTL != 3600 || cfg.MinTTL != 60 || cfg.Port != 53 ||
		cfg.AxfrTimeout != 30*time.Second || cfg.UpdateTimeout != 15*time.Second ||
		cfg.CircuitBreakerThreshold != 3 {
		t.Fatalf("defaults: %+v", cfg)
	}
}

// PROJECT_LABEL and INSTANCE_ID are deliberately NOT read by the sidecar
// — ownership is operator-side. Verify the sidecar starts cleanly even
// when those env vars are present (i.e. they're treated as inert).
func TestLoad_IgnoresProjectLabelAndInstanceID(t *testing.T) {
	os.Clearenv()
	withRequiredEnv(t)
	t.Setenv("PROJECT_LABEL", "my-op")
	t.Setenv("INSTANCE_ID", "42")
	if _, err := Load(); err != nil {
		t.Fatalf("unexpected: %v", err)
	}
}

func TestLoad_HostsMissing(t *testing.T) {
	os.Clearenv()
	t.Setenv("RFC2136_KERBEROS_REALM", "CORP.EXAMPLE.COM")
	t.Setenv("RFC2136_KERBEROS_PRINCIPAL", "svc-dns@CORP.EXAMPLE.COM")
	t.Setenv("RFC2136_KEYTAB_FILE", "/run/secrets/keytab")
	t.Setenv("RFC2136_ZONES", "corp.example.com")
	if _, err := Load(); err == nil {
		t.Fatalf("expected error when RFC2136_HOSTS missing")
	}
}

func TestLoad_ZonesMissing(t *testing.T) {
	os.Clearenv()
	t.Setenv("RFC2136_KERBEROS_REALM", "CORP.EXAMPLE.COM")
	t.Setenv("RFC2136_KERBEROS_PRINCIPAL", "svc-dns@CORP.EXAMPLE.COM")
	t.Setenv("RFC2136_KEYTAB_FILE", "/run/secrets/keytab")
	t.Setenv("RFC2136_HOSTS", "dc01.corp.example.com")
	if _, err := Load(); err == nil {
		t.Fatalf("expected error when RFC2136_ZONES missing")
	}
}
