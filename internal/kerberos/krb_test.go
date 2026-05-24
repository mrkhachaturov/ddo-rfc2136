package kerberos

import (
	"errors"
	"testing"
)

type stubExec struct {
	err          error
	lastName     string
	lastArgs     []string
	lastStdin    string
	stdinPasses  int
	keytabPasses int
}

func (s *stubExec) Run(name string, args ...string) error {
	s.lastName = name
	s.lastArgs = args
	s.keytabPasses++
	return s.err
}

func (s *stubExec) RunWithStdin(name string, stdin string, args ...string) error {
	s.lastName = name
	s.lastArgs = args
	s.lastStdin = stdin
	s.stdinPasses++
	return s.err
}

func TestKinit_Success(t *testing.T) {
	k := &Kinit{Exec: &stubExec{err: nil}}
	if err := k.Run("/etc/krb5.conf", "/run/secrets/keytab", "svc-dns@CORP.EXAMPLE.COM"); err != nil {
		t.Fatalf("unexpected: %v", err)
	}
}

func TestKinit_Failure(t *testing.T) {
	k := &Kinit{Exec: &stubExec{err: errors.New("kinit: KDC unreachable")}}
	if err := k.Run("/etc/krb5.conf", "/run/secrets/keytab", "svc-dns@CORP.EXAMPLE.COM"); err == nil {
		t.Fatalf("expected propagated error")
	}
}

func TestKinit_RunWithPasswordPipesStdinAndUsesNoKeytabFlag(t *testing.T) {
	exec := &stubExec{}
	k := &Kinit{Exec: exec}
	if err := k.RunWithPassword("/etc/krb5.conf", "svc-dns@CORP.EXAMPLE.COM", "hunter2"); err != nil {
		t.Fatalf("unexpected: %v", err)
	}
	if exec.lastName != "kinit" {
		t.Fatalf("kinit binary not invoked: %s", exec.lastName)
	}
	if len(exec.lastArgs) != 1 || exec.lastArgs[0] != "svc-dns@CORP.EXAMPLE.COM" {
		t.Fatalf("expected single principal arg, got %v", exec.lastArgs)
	}
	for _, a := range exec.lastArgs {
		if a == "-kt" {
			t.Fatalf("password mode must not pass -kt: %v", exec.lastArgs)
		}
	}
	if exec.lastStdin != "hunter2\n" {
		t.Fatalf("password not piped as-expected: %q", exec.lastStdin)
	}
	if exec.stdinPasses != 1 || exec.keytabPasses != 0 {
		t.Fatalf("wrong dispatch: stdin=%d keytab=%d", exec.stdinPasses, exec.keytabPasses)
	}
}

func TestKinit_RunWithPasswordTrimsTrailingNewline(t *testing.T) {
	exec := &stubExec{}
	k := &Kinit{Exec: exec}
	if err := k.RunWithPassword("/etc/krb5.conf", "svc-dns@CORP.EXAMPLE.COM", "hunter2\r\n"); err != nil {
		t.Fatalf("unexpected: %v", err)
	}
	if exec.lastStdin != "hunter2\n" {
		t.Fatalf("expected single trailing newline, got %q", exec.lastStdin)
	}
}

func TestKinit_RunWithPasswordPropagatesError(t *testing.T) {
	k := &Kinit{Exec: &stubExec{err: errors.New("preauth failed")}}
	if err := k.RunWithPassword("/etc/krb5.conf", "svc-dns@CORP.EXAMPLE.COM", "wrong"); err == nil {
		t.Fatalf("expected propagated error")
	}
}
