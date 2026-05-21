package kerberos

import (
	"errors"
	"testing"
)

type stubExec struct {
	err error
}

func (s stubExec) Run(name string, args ...string) error {
	return s.err
}

func TestKinit_Success(t *testing.T) {
	k := &Kinit{Exec: stubExec{err: nil}}
	if err := k.Run("/etc/krb5.conf", "/run/secrets/keytab", "svc-dns@CORP.EXAMPLE.COM"); err != nil {
		t.Fatalf("unexpected: %v", err)
	}
}

func TestKinit_Failure(t *testing.T) {
	k := &Kinit{Exec: stubExec{err: errors.New("kinit: KDC unreachable")}}
	if err := k.Run("/etc/krb5.conf", "/run/secrets/keytab", "svc-dns@CORP.EXAMPLE.COM"); err == nil {
		t.Fatalf("expected propagated error")
	}
}
