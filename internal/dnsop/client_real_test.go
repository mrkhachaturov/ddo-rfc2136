package dnsop

import (
	"errors"
	"testing"

	"github.com/miekg/dns"
)

// TestClassifyExchangeResult covers the unverifiable-reply branch (the server
// applied the change but never authenticated us) and the surrounding
// error/response classification branches in classifyExchangeResult.
func TestClassifyExchangeResult(t *testing.T) {
	makeResp := func(rcode int) *dns.Msg {
		m := new(dns.Msg)
		m.Response = true
		m.Rcode = rcode
		return m
	}

	tests := []struct {
		name      string
		resp      *dns.Msg
		err       error
		wantOK    bool
		wantRcode string
		wantPhase string
		wantRetry bool
	}{
		{
			// The server wrote the record but signed nothing we can check, so
			// it never verified us either: the write went in unauthenticated.
			// Reported as applied because the record is really there — the
			// warning, not the result, is what carries the diagnosis.
			name:      "unverifiable reply on NOERROR is still reported as applied",
			resp:      makeResp(dns.RcodeSuccess),
			err:       errors.New("dns: bad tsig"),
			wantOK:    true,
			wantRcode: "NOERROR",
		},
		{
			name:      "no response with err is a retryable dns-send failure",
			resp:      nil,
			err:       errors.New("dial tcp: connection refused"),
			wantOK:    false,
			wantPhase: "dns-send",
			wantRetry: true,
		},
		{
			name:      "no response with BADTIME err is tsig-verify retryable (clock skew)",
			resp:      nil,
			err:       errors.New("tsig: BADTIME (server time differs from client)"),
			wantOK:    false,
			wantPhase: "tsig-verify",
			wantRetry: true,
		},
		{
			name:      "no response with BADSIG err is tsig-verify non-retryable",
			resp:      nil,
			err:       errors.New("tsig: BADSIG signature verification failed"),
			wantOK:    false,
			wantPhase: "tsig-verify",
			wantRetry: false,
		},
		{
			name:      "no response with BADKEY err is tsig-verify non-retryable",
			resp:      nil,
			err:       errors.New("tsig: BADKEY key name not recognised"),
			wantOK:    false,
			wantPhase: "tsig-verify",
			wantRetry: false,
		},
		{
			name:      "no response with 'bad signature' err (lowercase variant) is tsig-verify non-retryable",
			resp:      nil,
			err:       errors.New("dns: bad signature on TSIG"),
			wantOK:    false,
			wantPhase: "tsig-verify",
			wantRetry: false,
		},
		{
			name:      "err with non-success Rcode is classified via ClassifyRcode (REFUSED)",
			resp:      makeResp(dns.RcodeRefused),
			err:       errors.New("dns: bad tsig"),
			wantOK:    false,
			wantRcode: "REFUSED",
			wantPhase: "dns-receive",
			wantRetry: false,
		},
		{
			name:      "err with SERVFAIL Rcode is retryable",
			resp:      makeResp(dns.RcodeServerFailure),
			err:       errors.New("dns: bad tsig"),
			wantOK:    false,
			wantRcode: "SERVFAIL",
			wantPhase: "dns-receive",
			wantRetry: true,
		},
		{
			name:   "no err with NOERROR response is success",
			resp:   makeResp(dns.RcodeSuccess),
			err:    nil,
			wantOK: true, wantRcode: "NOERROR",
		},
		{
			name:      "no err with nil response is a retryable receive failure",
			resp:      nil,
			err:       nil,
			wantOK:    false,
			wantPhase: "dns-receive",
			wantRetry: true,
		},
		{
			name:      "no err with REFUSED response is classified",
			resp:      makeResp(dns.RcodeRefused),
			err:       nil,
			wantOK:    false,
			wantRcode: "REFUSED",
			wantPhase: "dns-receive",
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			got := classifyExchangeResult(tc.resp, tc.err)
			if got.OK != tc.wantOK {
				t.Errorf("OK: got %v want %v (full=%+v)", got.OK, tc.wantOK, got)
			}
			if tc.wantRcode != "" && got.Rcode != tc.wantRcode {
				t.Errorf("Rcode: got %q want %q", got.Rcode, tc.wantRcode)
			}
			if tc.wantPhase != "" && got.Phase != tc.wantPhase {
				t.Errorf("Phase: got %q want %q", got.Phase, tc.wantPhase)
			}
			if got.Retryable != tc.wantRetry {
				t.Errorf("Retryable: got %v want %v", got.Retryable, tc.wantRetry)
			}
		})
	}
}
