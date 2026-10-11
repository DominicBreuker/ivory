//go:build ivory

package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/DominicBreuker/ivory/cmd/ivory/internal/wire"
)

// handshakeInfo is what a handshake negotiated, or how it failed.
type handshakeInfo struct {
	OK       bool    `json:"ok"`
	Error    string  `json:"error,omitempty"`
	Duration float64 `json:"duration_seconds"`
	// AlertSent and AlertReceived are the first plaintext alerts; alerts
	// after the handshake keys are encrypted and appear in Error only.
	AlertSent     string `json:"alert_sent,omitempty"`
	AlertReceived string `json:"alert_received,omitempty"`

	Version           wire.Version         `json:"version,omitempty"`
	CipherSuite       wire.CipherSuite     `json:"cipher_suite,omitempty"`
	Group             wire.Group           `json:"group,omitempty"`
	ServerSignature   wire.SignatureScheme `json:"server_signature,omitempty"`
	ALPN              string               `json:"alpn,omitempty"`
	Resumed           bool                 `json:"resumed,omitempty"`
	HelloRetryRequest bool                 `json:"hello_retry_request,omitempty"`
	// ServerExtensions are the extensions of the ServerHello.
	ServerExtensions     []wire.ExtensionType `json:"server_extensions,omitempty"`
	ExtendedMasterSecret bool                 `json:"extended_master_secret,omitempty"`
	SecureRenegotiation  bool                 `json:"secure_renegotiation,omitempty"`
	OCSPStapled          bool                 `json:"ocsp_stapled,omitempty"`
	DowngradeSentinel    string               `json:"downgrade_sentinel,omitempty"`
}

// fill sets the fields from the connection state (if the handshake
// completed) and from the decoded handshake messages. local is the
// direction of our own records.
func (hi *handshakeInfo) fill(state *tls.ConnectionState, log *handshakeLog, local string) {
	log.mu.Lock()
	defer log.mu.Unlock()
	remote := dirS2C
	if local == dirS2C {
		remote = dirC2S
	}
	if a := log.alerts[local]; a != nil {
		hi.AlertSent = a.String()
	}
	if a := log.alerts[remote]; a != nil {
		hi.AlertReceived = a.String()
	}
	if sh := log.serverHello; sh != nil {
		hi.Version, hi.CipherSuite = sh.Negotiated(), sh.CipherSuite
		for _, e := range sh.Extensions {
			hi.ServerExtensions = append(hi.ServerExtensions, e.Type)
		}
		hi.ExtendedMasterSecret = sh.Has(wire.ExtExtendedMasterSecret) || hi.Version == wire.VersionTLS13
		hi.SecureRenegotiation = sh.Has(wire.ExtRenegotiationInfo)
		hi.ALPN = sh.ALPN
		hi.DowngradeSentinel = sh.Downgrade
		if sh.KeyShare != 0 {
			hi.Group = sh.KeyShare
		}
	}
	if log.ske != nil {
		hi.Group, hi.ServerSignature = log.ske.Group, log.ske.SignatureScheme
	}
	hi.OCSPStapled = log.stapled
	if state != nil {
		hi.Version, hi.CipherSuite = wire.Version(state.Version), wire.CipherSuite(state.CipherSuite)
		if state.CurveID != 0 {
			hi.Group = wire.Group(state.CurveID)
		}
		hi.ALPN, hi.Resumed, hi.HelloRetryRequest = state.NegotiatedProtocol, state.DidResume, state.HelloRetryRequest
		hi.OCSPStapled = hi.OCSPStapled || len(state.OCSPResponse) > 0
	}
}

func (hi *handshakeInfo) print(w io.Writer) {
	if hi.OK {
		kv(w, "handshake", fmt.Sprintf("ok (%.3f s)", hi.Duration))
	} else {
		kv(w, "handshake", "FAILED: "+hi.Error)
	}
	if hi.AlertReceived != "" {
		kv(w, "alert received", hi.AlertReceived)
	}
	if hi.AlertSent != "" {
		kv(w, "alert sent", hi.AlertSent)
	}
	if hi.Version != 0 {
		kv(w, "version", hi.Version.String())
	}
	if hi.CipherSuite != 0 {
		kv(w, "cipher suite", hi.CipherSuite.String())
	}
	if hi.Group != 0 {
		kv(w, "group", hi.Group.String())
	}
	if hi.ServerSignature != 0 {
		kv(w, "server signature", hi.ServerSignature.String())
	}
	if hi.ALPN != "" {
		kv(w, "ALPN", hi.ALPN)
	}
	if hi.Version != 0 {
		var flags []string
		if hi.Resumed {
			flags = append(flags, "resumed")
		}
		if hi.HelloRetryRequest {
			flags = append(flags, "HelloRetryRequest")
		}
		if hi.ExtendedMasterSecret {
			flags = append(flags, "extended master secret")
		}
		if hi.SecureRenegotiation {
			flags = append(flags, "secure renegotiation")
		}
		if hi.OCSPStapled {
			flags = append(flags, "OCSP stapled")
		}
		if hi.DowngradeSentinel != "" {
			flags = append(flags, "downgrade sentinel "+hi.DowngradeSentinel)
		}
		if len(flags) > 0 {
			kv(w, "features", strings.Join(flags, ", "))
		}
		if hi.ServerExtensions != nil {
			kv(w, "server extensions", joinNames(hi.ServerExtensions))
		}
	}
}

// certRequestInfo is what a server asked for in its CertificateRequest.
type certRequestInfo struct {
	CertificateTypes []string               `json:"certificate_types,omitempty"`
	SignatureSchemes []wire.SignatureScheme `json:"signature_schemes,omitempty"`
	CAs              []string               `json:"certificate_authorities"`
}

func (cr *certRequestInfo) print(w io.Writer) {
	if cr.CertificateTypes != nil {
		kv(w, "certificate types", strings.Join(cr.CertificateTypes, ", "))
	}
	kv(w, "signature schemes", joinNames(cr.SignatureSchemes))
	kv(w, "acceptable CAs", fmt.Sprintf("%d", len(cr.CAs)))
	for _, ca := range cr.CAs {
		fmt.Fprintf(w, "    %s\n", ca)
	}
}

// chainReport describes a peer's certificate chain and its TI check.
type chainReport struct {
	Certificates []CertInfo `json:"certificates"`
	TICheck      *TICheck   `json:"ti_check,omitempty"`
}

func newChainReport(ctx context.Context, ders [][]byte, ts *trustSpace) *chainReport {
	if len(ders) == 0 {
		return nil
	}
	r := &chainReport{}
	for _, der := range ders {
		r.Certificates = append(r.Certificates, describeDER(der))
	}
	if ts != nil {
		if leaf, err := x509.ParseCertificate(ders[0]); err == nil {
			r.TICheck = ts.check(ctx, leaf)
		} else {
			r.TICheck = &TICheck{Environment: ts.env, Result: "failed", Error: err.Error()}
		}
	}
	return r
}

func (r *chainReport) print(w io.Writer) {
	for i, c := range r.Certificates {
		fmt.Fprintf(w, "  [%d]\n", i)
		printCert(w, c, "    ")
	}
	if t := r.TICheck; t != nil {
		title := "TI check"
		if t.Environment != "" {
			title += " (" + strings.ToUpper(t.Environment) + ")"
		}
		fmt.Fprintln(w, title)
		if t.TSLSequence != 0 {
			kv(w, "TSL sequence", fmt.Sprint(t.TSLSequence))
		}
		if t.IssuerCA != "" {
			kv(w, "issuing CA", t.IssuerCA)
		}
		if t.IssuerService != "" {
			kv(w, "CA in TSL", t.IssuerService+" ("+t.IssuerStatus+")")
		}
		if t.OCSP != "" {
			ocspLine := t.OCSP
			if t.OCSPResponder != "" {
				ocspLine += " from " + t.OCSPResponder
			}
			kv(w, "OCSP", ocspLine)
		}
		if t.Result == "ok" {
			kv(w, "result", "ok")
		} else {
			kv(w, "result", "FAILED: "+t.Error)
		}
	}
}

func printCert(w io.Writer, c CertInfo, indent string) {
	line := func(k, v string) { fmt.Fprintf(w, "%s%-17s %s\n", indent, k, v) }
	if c.Error != "" {
		line("error", c.Error)
		line("sha256", c.SHA256)
		return
	}
	line("subject", c.Subject)
	line("issuer", c.Issuer)
	line("serial", c.Serial)
	line("validity", c.NotBefore.Format(time.RFC3339)+" to "+c.NotAfter.Format(time.RFC3339)+validityNote(c))
	line("key", c.Key)
	line("signature", c.SignatureAlg)
	if c.IsCA {
		line("CA", "yes")
	}
	if c.KeyUsage != nil {
		line("key usage", strings.Join(c.KeyUsage, ", "))
	}
	if c.ExtKeyUsage != nil {
		line("ext. key usage", strings.Join(c.ExtKeyUsage, ", "))
	}
	if c.Types != nil {
		line("TI type", strings.Join(c.Types, ", "))
	}
	for _, p := range c.Policies {
		line("policy", p.String())
	}
	if c.Admission != nil {
		for _, p := range c.Admission.Professions {
			if len(p.Items) > 0 {
				line("role", strings.Join(p.Items, "; "))
			}
			for _, o := range p.OIDs {
				line("  role OID", o.String())
			}
			if p.RegistrationNumber != "" {
				line("  registration", p.RegistrationNumber)
			}
		}
	}
	if names := append(append(append([]string{}, c.DNSNames...), c.IPs...), c.Emails...); len(names) > 0 {
		line("names", strings.Join(names, ", "))
	}
	for _, o := range c.OCSP {
		line("OCSP", o)
	}
	line("sha256", c.SHA256)
}

func validityNote(c CertInfo) string {
	now := time.Now()
	switch {
	case now.Before(c.NotBefore):
		return " (NOT YET VALID)"
	case now.After(c.NotAfter):
		return " (EXPIRED)"
	}
	return ""
}

func kv(w io.Writer, k, v string) { fmt.Fprintf(w, "  %-17s %s\n", k, v) }

func joinNames[T interface{ Name() string }](v []T) string {
	if len(v) == 0 {
		return "(none)"
	}
	s := make([]string, len(v))
	for i, x := range v {
		s[i] = x.Name()
	}
	return strings.Join(s, ", ")
}

func writeJSON(w io.Writer, v any, indent bool) error {
	enc := json.NewEncoder(w)
	if indent {
		enc.SetIndent("", "  ")
	}
	return enc.Encode(v)
}
