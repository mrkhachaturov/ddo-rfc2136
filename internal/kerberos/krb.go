package kerberos

import (
	"fmt"
	"os"
	"os/exec"
)

// Executor abstracts os/exec for testing.
type Executor interface {
	Run(name string, args ...string) error
}

type RealExec struct{}

func (RealExec) Run(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

type Kinit struct {
	Exec Executor
}

// Run executes kinit -kt <keytab> <principal> with KRB5_CONFIG pointing to krb5conf.
// It also sets KRB5CCNAME to a process-local credential cache so the ticket is
// inherited by subsequent dial/sign calls without contaminating the system ccache.
func (k *Kinit) Run(krb5conf, keytab, principal string) error {
	if err := os.Setenv("KRB5_CONFIG", krb5conf); err != nil {
		return fmt.Errorf("set KRB5_CONFIG: %w", err)
	}
	if err := os.Setenv("KRB5CCNAME", fmt.Sprintf("FILE:/tmp/krb5cc_%d", os.Getpid())); err != nil {
		return fmt.Errorf("set KRB5CCNAME: %w", err)
	}
	if err := k.Exec.Run("kinit", "-kt", keytab, principal); err != nil {
		return fmt.Errorf("kinit failed: %w", err)
	}
	return nil
}
