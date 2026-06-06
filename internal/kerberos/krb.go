package kerberos

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/jcmturner/gokrb5/v8/credentials"
)

// Executor abstracts os/exec for testing.
type Executor interface {
	Run(name string, args ...string) error
	// RunWithStdin is like Run but feeds stdin to the child process. Used for
	// password-based kinit, which reads the password from stdin when no tty is
	// attached.
	RunWithStdin(name string, stdin string, args ...string) error
}

type RealExec struct{}

func (RealExec) Run(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func (RealExec) RunWithStdin(name string, stdin string, args ...string) error {
	cmd := exec.Command(name, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	pipe, err := cmd.StdinPipe()
	if err != nil {
		return err
	}
	if err := cmd.Start(); err != nil {
		return err
	}
	_, _ = io.WriteString(pipe, stdin)
	_ = pipe.Close()
	return cmd.Wait()
}

type Kinit struct {
	Exec Executor
}

func (k *Kinit) prepareEnv(krb5conf string) error {
	if err := os.Setenv("KRB5_CONFIG", krb5conf); err != nil {
		return fmt.Errorf("set KRB5_CONFIG: %w", err)
	}
	if err := os.Setenv("KRB5CCNAME", fmt.Sprintf("FILE:/tmp/krb5cc_%d", os.Getpid())); err != nil {
		return fmt.Errorf("set KRB5CCNAME: %w", err)
	}
	return nil
}

// Run executes kinit -kt <keytab> <principal> with KRB5_CONFIG pointing to krb5conf.
// It also sets KRB5CCNAME to a process-local credential cache so the ticket is
// inherited by subsequent dial/sign calls without contaminating the system ccache.
func (k *Kinit) Run(krb5conf, keytab, principal string) error {
	if err := k.prepareEnv(krb5conf); err != nil {
		return err
	}
	if err := k.Exec.Run("kinit", "-kt", keytab, principal); err != nil {
		return fmt.Errorf("kinit failed: %w", err)
	}
	return nil
}

// CCachePath returns the process-local credential cache path that kinit
// writes to (matching the KRB5CCNAME prepareEnv sets). The refresher reads
// the issued TGT's endtime from here after each successful kinit.
func CCachePath() string {
	return fmt.Sprintf("/tmp/krb5cc_%d", os.Getpid())
}

// CCacheLifetime is a LifetimeSource backed by the on-disk credential cache.
// It reads the krbtgt entry's EndTime so the refresher can schedule the next
// kinit from the lifetime the KDC actually granted.
type CCacheLifetime struct {
	// Path is the ccache file path. Empty defaults to CCachePath().
	Path string
}

// TGTEndTime parses the ccache and returns the expiry of the
// ticket-granting ticket (server principal krbtgt/...). If no krbtgt entry is
// found it falls back to the latest EndTime across all entries.
func (c CCacheLifetime) TGTEndTime() (time.Time, error) {
	path := c.Path
	if path == "" {
		path = CCachePath()
	}
	cc, err := credentials.LoadCCache(path)
	if err != nil {
		return time.Time{}, fmt.Errorf("load ccache %s: %w", path, err)
	}
	var tgt, latest time.Time
	for _, cred := range cc.GetEntries() {
		nm := cred.Server.PrincipalName.NameString
		if len(nm) > 0 && strings.EqualFold(nm[0], "krbtgt") {
			if cred.EndTime.After(tgt) {
				tgt = cred.EndTime
			}
		}
		if cred.EndTime.After(latest) {
			latest = cred.EndTime
		}
	}
	if !tgt.IsZero() {
		return tgt, nil
	}
	if !latest.IsZero() {
		return latest, nil
	}
	return time.Time{}, fmt.Errorf("ccache %s has no usable credential endtime", path)
}

// RunWithPassword executes `kinit <principal>` and feeds the password via stdin.
// Both MIT and Heimdal kinit read the password from stdin when no tty is
// attached, which is the case under a container's PID 1.
func (k *Kinit) RunWithPassword(krb5conf, principal, password string) error {
	if err := k.prepareEnv(krb5conf); err != nil {
		return err
	}
	// kinit reads a single line, terminated by newline.
	stdin := strings.TrimRight(password, "\r\n") + "\n"
	if err := k.Exec.RunWithStdin("kinit", stdin, principal); err != nil {
		return fmt.Errorf("kinit (password) failed: %w", err)
	}
	return nil
}
