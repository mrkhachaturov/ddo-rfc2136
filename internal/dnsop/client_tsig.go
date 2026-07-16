package dnsop

import (
	"net"
	"strconv"
	"time"

	"github.com/bodgit/tsig"
	"github.com/miekg/dns"
)

// tsigFudge is the TSIG time window in seconds — how much clock skew the
// server will tolerate on our signature. 300 is what RealClient sends and what
// upstream external-dns uses.
const tsigFudge = 300

// TSIGClient speaks RFC 2136 signed with a pre-shared HMAC key (RFC 8945), or
// unsigned when Insecure is set. It is the non-Kerberos half of Client:
// everything below the signature — building the UPDATE, parsing the AXFR
// stream, classifying the rcode — is shared with RealClient verbatim.
//
// Unlike RealClient there is no context to negotiate and nothing to tear down,
// so a single value is safe to reuse across hosts and goroutines.
type TSIGClient struct {
	// KeyName and Algorithm are in FQDN form; config canonicalises them and
	// validates Algorithm against the supported set, so nothing here re-checks.
	KeyName   string
	Secret    string
	Algorithm string
	// Insecure sends unsigned messages, leaving authorisation entirely to the
	// server's network ACL. KeyName/Secret/Algorithm are unused when set.
	Insecure      bool
	AxfrTimeout   time.Duration
	UpdateTimeout time.Duration

	// exchange sends the UPDATE and reads the reply. Defaults to
	// (*dns.Client).Exchange when nil; tests override it to drive transport and
	// TSIG-verify behaviour without a live DNS server.
	exchange func(client *dns.Client, m *dns.Msg, addr string) (*dns.Msg, time.Duration, error)
}

// sign attaches the TSIG RR to m and returns the provider that will compute the
// MAC, or nil in insecure mode. Both the Transfer and the Client take the
// provider the same way, so AXFR and Update share this.
func (c *TSIGClient) sign(m *dns.Msg) dns.TsigProvider {
	if c.Insecure {
		return nil
	}
	m.SetTsig(c.KeyName, c.Algorithm, tsigFudge, time.Now().Unix())
	return tsig.HMAC{c.KeyName: c.Secret}
}

func (c *TSIGClient) AXFR(host string, port int, zone string) RecordsResult {
	addr := net.JoinHostPort(host, strconv.Itoa(port))

	m := new(dns.Msg)
	m.SetAxfr(dns.Fqdn(zone))

	t := &dns.Transfer{
		TsigProvider: c.sign(m),
		DialTimeout:  c.AxfrTimeout,
		ReadTimeout:  c.AxfrTimeout,
	}
	ch, err := t.In(m, addr)
	if err != nil {
		return RecordsResult{OK: false, Phase: "dns-send", Message: err.Error(), Retryable: true}
	}
	return ParseAXFRStream(ch)
}

func (c *TSIGClient) Update(host string, port int, zone string, prereqs []Prereq, changes []Change) ApplyResult {
	addr := net.JoinHostPort(host, strconv.Itoa(port))

	m, err := BuildUpdateMsg(zone, prereqs, changes)
	if err != nil {
		return ApplyResult{OK: false, Phase: "dns-send", Message: err.Error(), Retryable: false}
	}

	cli := &dns.Client{
		Net:          "tcp",
		TsigProvider: c.sign(m),
		DialTimeout:  c.UpdateTimeout,
		ReadTimeout:  c.UpdateTimeout,
		WriteTimeout: c.UpdateTimeout,
	}

	exchange := c.exchange
	if exchange == nil {
		exchange = func(client *dns.Client, msg *dns.Msg, a string) (*dns.Msg, time.Duration, error) {
			return client.Exchange(msg, a)
		}
	}

	resp, _, err := exchange(cli, m, addr)
	return classifyExchangeResult(resp, err)
}

// NewTSIGClient is the main.go wiring counterpart to NewRealClient. It cannot
// fail: there is no context to establish up front.
func NewTSIGClient(keyName, secret, algorithm string, insecure bool, axfr, upd time.Duration) *TSIGClient {
	return &TSIGClient{
		KeyName:       keyName,
		Secret:        secret,
		Algorithm:     algorithm,
		Insecure:      insecure,
		AxfrTimeout:   axfr,
		UpdateTimeout: upd,
	}
}
