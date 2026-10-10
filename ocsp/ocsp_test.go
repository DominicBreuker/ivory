package ocsp

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/DominicBreuker/ivory/internal/testpki"
	"golang.org/x/crypto/cryptobyte"
	xocsp "golang.org/x/crypto/ocsp"
)

var now = time.Date(2030, 1, 1, 12, 0, 0, 0, time.UTC)

// fixture is a CA, a certificate it issued, and an OCSP signer.
type fixture struct {
	ca, leaf, responder *x509.Certificate
	caKey, responderKey crypto.Signer
}

func newFixture(t testing.TB, caKey, responderKey crypto.Signer) *fixture {
	t.Helper()
	f := &fixture{caKey: caKey, responderKey: responderKey}
	f.ca = testpki.Issue(t, testpki.CA("Test CA"), caKey, nil, caKey)
	f.leaf = testpki.Issue(t, testpki.EE("leaf", x509.KeyUsageDigitalSignature), testpki.P256(t), f.ca, caKey)
	f.responder = testpki.Issue(t, testpki.EE("OCSP Signer", x509.KeyUsageDigitalSignature, x509.ExtKeyUsageOCSPSigning), responderKey, f.ca, caKey)
	return f
}

// good returns a template for a good response about f.leaf.
func (f *fixture) good(t testing.TB) ResponseTemplate {
	t.Helper()
	id, err := NewCertID(f.leaf, f.ca, crypto.SHA1)
	if err != nil {
		t.Fatal(err)
	}
	return ResponseTemplate{
		ProducedAt: now,
		Responses: []SingleResponse{{
			CertID:     id,
			Status:     Good,
			ThisUpdate: now,
			NextUpdate: now.Add(time.Hour),
			CertHash:   NewCertHash(f.leaf),
		}},
		Certificates: [][]byte{f.responder.Raw},
	}
}

func (f *fixture) create(t testing.TB, tmpl ResponseTemplate) []byte {
	t.Helper()
	der, err := CreateResponse(tmpl, f.responder, f.responderKey)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func (f *fixture) opts() VerifyOptions {
	return VerifyOptions{Issuer: f.ca, Responders: []*x509.Certificate{f.responder}, Time: now}
}

func verify(t testing.TB, der []byte, cert *x509.Certificate, opts VerifyOptions) (*SingleResponse, error) {
	t.Helper()
	r, err := ParseResponse(der)
	if err != nil {
		t.Fatalf("ParseResponse: %v", err)
	}
	return r.Verify(cert, opts)
}

func newRSA(t testing.TB) *rsa.PrivateKey {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func TestVerifyGood(t *testing.T) {
	for _, tc := range []struct {
		name string
		key  func(testing.TB) crypto.Signer
	}{
		{"P-256", func(t testing.TB) crypto.Signer { return testpki.P256(t) }},
		{"RSA", func(t testing.TB) crypto.Signer { return newRSA(t) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t, testpki.P256(t), tc.key(t))
			sr, err := verify(t, f.create(t, f.good(t)), f.leaf, f.opts())
			if err != nil {
				t.Fatal(err)
			}
			if sr.Status != Good || sr.CertHash == nil || sr.CertHash.HashAlgorithm != crypto.SHA256 {
				t.Errorf("got %+v", sr)
			}
		})
	}
}

func TestVerifyErrors(t *testing.T) {
	f := newFixture(t, testpki.P256(t), testpki.P256(t))
	other := testpki.Issue(t, testpki.EE("other", x509.KeyUsageDigitalSignature), testpki.P256(t), f.ca, f.caKey)
	// A signer with the responder's name but another key.
	impostorKey := testpki.P256(t)
	impostor := testpki.Issue(t, testpki.EE("OCSP Signer", x509.KeyUsageDigitalSignature), impostorKey, f.ca, f.caKey)

	for _, tc := range []struct {
		name   string
		modify func(*ResponseTemplate)
		opts   func(*VerifyOptions)
		sign   func(ResponseTemplate) []byte
		want   error // nil: valid
	}{
		{name: "good"},
		{name: "byName", modify: func(r *ResponseTemplate) { r.ResponderByName = true }},
		{name: "no certificates", modify: func(r *ResponseTemplate) { r.Certificates = nil }},
		{name: "untrusted responder", opts: func(o *VerifyOptions) { o.Responders = []*x509.Certificate{other} }, want: ErrCertMissing},
		{name: "no responders", opts: func(o *VerifyOptions) { o.Responders = nil }, want: ErrCertMissing},
		{name: "impostor byName", modify: func(r *ResponseTemplate) { r.ResponderByName = true },
			sign: func(r ResponseTemplate) []byte {
				der, err := CreateResponse(r, impostor, impostorKey)
				if err != nil {
					t.Fatal(err)
				}
				return der
			}, want: ErrSignature},
		{name: "other certificate", opts: func(o *VerifyOptions) {}, want: ErrCheckRevocation},
		{name: "SHA-256 CertID", modify: func(r *ResponseTemplate) {
			r.Responses[0].CertID, _ = NewCertID(f.leaf, f.ca, crypto.SHA256)
		}},
		{name: "CertID without NULL", modify: func(r *ResponseTemplate) { r.Responses[0].CertID.HashParametersNull = false }},
		{name: "wrong serial", modify: func(r *ResponseTemplate) { r.Responses[0].CertID.SerialNumber = big.NewInt(1) }, want: ErrCheckRevocation},
		{name: "wrong issuer name hash", modify: func(r *ResponseTemplate) { r.Responses[0].CertID.IssuerNameHash[0] ^= 1 }, want: ErrCheckRevocation},
		{name: "wrong issuer key hash", modify: func(r *ResponseTemplate) { r.Responses[0].CertID.IssuerKeyHash[0] ^= 1 }, want: ErrCheckRevocation},
		{name: "producedAt past within", modify: func(r *ResponseTemplate) { r.ProducedAt = now.Add(-37 * time.Second) }},
		{name: "producedAt past out", modify: func(r *ResponseTemplate) { r.ProducedAt = now.Add(-38 * time.Second) }, want: ErrCheckRevocation},
		{name: "producedAt future within", modify: func(r *ResponseTemplate) { r.ProducedAt = now.Add(37 * time.Second) }},
		{name: "producedAt future out", modify: func(r *ResponseTemplate) { r.ProducedAt = now.Add(38 * time.Second) }, want: ErrCheckRevocation},
		{name: "producedAt custom tolerance", modify: func(r *ResponseTemplate) { r.ProducedAt = now.Add(-6 * time.Second) },
			opts: func(o *VerifyOptions) { o.ProducedAtPast = 5 * time.Second }, want: ErrCheckRevocation},
		{name: "thisUpdate future within", modify: func(r *ResponseTemplate) { r.Responses[0].ThisUpdate = now.Add(37 * time.Second) }},
		{name: "thisUpdate future out", modify: func(r *ResponseTemplate) { r.Responses[0].ThisUpdate = now.Add(38 * time.Second) }, want: ErrCheckRevocation},
		{name: "nextUpdate past within", modify: func(r *ResponseTemplate) { r.Responses[0].NextUpdate = now.Add(-37 * time.Second) }},
		{name: "nextUpdate past out", modify: func(r *ResponseTemplate) { r.Responses[0].NextUpdate = now.Add(-38 * time.Second) }, want: ErrCheckRevocation},
		{name: "no nextUpdate", modify: func(r *ResponseTemplate) { r.Responses[0].NextUpdate = time.Time{} }},
		{name: "certHash missing", modify: func(r *ResponseTemplate) { r.Responses[0].CertHash = nil }, want: ErrCertHashMissing},
		{name: "certHash missing, check off", modify: func(r *ResponseTemplate) { r.Responses[0].CertHash = nil },
			opts: func(o *VerifyOptions) { o.SkipCertHash = true }},
		{name: "certHash mismatch", modify: func(r *ResponseTemplate) { r.Responses[0].CertHash = NewCertHash(other) }, want: ErrCertHashMismatch},
		{name: "revoked", modify: func(r *ResponseTemplate) {
			r.Responses[0].Status, r.Responses[0].RevokedAt, r.Responses[0].RevocationReason = Revoked, now.Add(-time.Hour), 1
		}, want: ErrRevoked},
		{name: "revoked later", modify: func(r *ResponseTemplate) {
			r.Responses[0].Status, r.Responses[0].RevokedAt = Revoked, now.Add(time.Hour)
		}},
		{name: "unknown", modify: func(r *ResponseTemplate) { r.Responses[0].Status = Unknown }, want: ErrUnknown},
		{name: "tryLater", modify: func(r *ResponseTemplate) { r.Status = TryLater }, want: ErrStatus},
		{name: "unauthorized", modify: func(r *ResponseTemplate) { r.Status = Unauthorized }, want: ErrStatus},
		{name: "nonce", modify: func(r *ResponseTemplate) {
			r.Extensions = []pkix.Extension{{Id: OIDNonce, Value: octetString([]byte("12345678"))}}
		}, opts: func(o *VerifyOptions) { o.Nonce = []byte("12345678") }},
		{name: "nonce mismatch", modify: func(r *ResponseTemplate) {
			r.Extensions = []pkix.Extension{{Id: OIDNonce, Value: octetString([]byte("12345678"))}}
		}, opts: func(o *VerifyOptions) { o.Nonce = []byte("87654321") }, want: ErrCheckRevocation},
		{name: "nonce missing", opts: func(o *VerifyOptions) { o.Nonce = []byte("87654321") }, want: ErrCheckRevocation},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tmpl := f.good(t)
			if tc.modify != nil {
				tc.modify(&tmpl)
			}
			var der []byte
			if tc.sign != nil {
				der = tc.sign(tmpl)
			} else {
				der = f.create(t, tmpl)
			}
			opts := f.opts()
			cert := f.leaf
			if tc.opts != nil {
				tc.opts(&opts)
				if tc.name == "other certificate" {
					cert = other
				}
			}
			_, err := verify(t, der, cert, opts)
			if tc.want == nil && err != nil || tc.want != nil && !errors.Is(err, tc.want) {
				t.Errorf("got %v, want %v", err, tc.want)
			}
		})
	}
}

func TestTamperedSignature(t *testing.T) {
	f := newFixture(t, testpki.P256(t), testpki.P256(t))
	r, err := ParseResponse(f.create(t, f.good(t)))
	if err != nil {
		t.Fatal(err)
	}
	r.TBSResponseData = append([]byte(nil), r.TBSResponseData...)
	r.TBSResponseData[len(r.TBSResponseData)-1] ^= 1
	if _, err := r.Verify(f.leaf, f.opts()); !errors.Is(err, ErrSignature) {
		t.Errorf("got %v, want ErrSignature", err)
	}
}

// TestXCryptoInterop checks this package against golang.org/x/crypto/ocsp
// in both directions, for keys both support.
func TestXCryptoInterop(t *testing.T) {
	f := newFixture(t, testpki.P256(t), testpki.P256(t))

	// x/crypto creates, this package verifies.
	ch := NewCertHash(f.leaf)
	var b cryptobyte.Builder
	b.AddASN1(0x30, func(b *cryptobyte.Builder) {
		b.AddASN1(0x30, func(b *cryptobyte.Builder) { b.AddASN1ObjectIdentifier(oidSHA256) })
		b.AddASN1OctetString(ch.Hash)
	})
	der, err := xocsp.CreateResponse(f.ca, f.responder, xocsp.Response{
		Status:          xocsp.Good,
		SerialNumber:    f.leaf.SerialNumber,
		ThisUpdate:      time.Now().Add(-time.Hour),
		NextUpdate:      time.Now().Add(time.Hour),
		ExtraExtensions: []pkix.Extension{{Id: OIDCertHash, Value: b.BytesOrPanic()}},
	}, f.responderKey.(crypto.Signer))
	if err != nil {
		t.Fatal(err)
	}
	r, err := ParseResponse(der)
	if err != nil {
		t.Fatal(err)
	}
	opts := f.opts()
	opts.Time = r.ProducedAt
	if _, err := r.Verify(f.leaf, opts); err != nil {
		t.Errorf("x/crypto response: %v", err)
	}

	// This package creates, x/crypto verifies.
	xr, err := xocsp.ParseResponseForCert(f.create(t, f.good(t)), f.leaf, f.ca)
	if err != nil {
		t.Fatalf("x/crypto: %v", err)
	}
	if xr.Status != xocsp.Good || xr.SerialNumber.Cmp(f.leaf.SerialNumber) != 0 || !xr.ProducedAt.Equal(now) {
		t.Errorf("x/crypto parsed %+v", xr)
	}

	// Requests both ways.
	req, err := CreateRequest(f.leaf, f.ca, &RequestOptions{Hash: crypto.SHA256})
	if err != nil {
		t.Fatal(err)
	}
	xreq, err := xocsp.ParseRequest(req)
	if err != nil {
		t.Fatal(err)
	}
	if xreq.HashAlgorithm != crypto.SHA256 || xreq.SerialNumber.Cmp(f.leaf.SerialNumber) != 0 {
		t.Errorf("x/crypto parsed request %+v", xreq)
	}
	xder, err := xocsp.CreateRequest(f.leaf, f.ca, nil)
	if err != nil {
		t.Fatal(err)
	}
	pr, err := ParseRequest(xder)
	if err != nil {
		t.Fatal(err)
	}
	if len(pr.CertIDs) != 1 || !pr.CertIDs[0].Matches(f.leaf, f.ca) || pr.CertIDs[0].HashAlgorithm != crypto.SHA1 {
		t.Errorf("parsed x/crypto request %+v", pr.CertIDs[0])
	}
}

func TestRequestRoundTrip(t *testing.T) {
	f := newFixture(t, testpki.P256(t), testpki.P256(t))
	der, err := CreateRequest(f.leaf, f.ca, &RequestOptions{Nonce: []byte("nonce-123")})
	if err != nil {
		t.Fatal(err)
	}
	r, err := ParseRequest(der)
	if err != nil {
		t.Fatal(err)
	}
	if !r.CertIDs[0].Matches(f.leaf, f.ca) || r.CertIDs[0].Matches(f.responder, f.ca) {
		t.Error("CertID doesn't match")
	}
	if string(r.Nonce()) != string(octetString([]byte("nonce-123"))) {
		t.Errorf("nonce %x", r.Nonce())
	}
}

func TestParseMalformed(t *testing.T) {
	f := newFixture(t, testpki.P256(t), testpki.P256(t))
	der := f.create(t, f.good(t))
	for i := range der {
		if _, err := ParseResponse(der[:i]); err == nil {
			t.Fatalf("truncated to %d bytes: no error", i)
		}
	}
	if _, err := ParseResponse(append(der, 0)); err == nil {
		t.Error("trailing byte: no error")
	}
}

func TestGeneralizedTime(t *testing.T) {
	for in, want := range map[string]string{
		"20300101120000Z":     "2030-01-01T12:00:00Z",
		"20300101120000.5Z":   "2030-01-01T12:00:00.5Z",
		"20300101120000.123Z": "2030-01-01T12:00:00.123Z",
		"20300101120000.50Z":  "",
		"20300101120000.Z":    "",
		"20300101120000":      "",
		"203001011200Z":       "",
		"20300101120000+0100": "",
	} {
		var b cryptobyte.Builder
		b.AddASN1(24, func(b *cryptobyte.Builder) { b.AddBytes([]byte(in)) })
		s := cryptobyte.String(b.BytesOrPanic())
		got, err := readGeneralizedTime(&s)
		if want == "" {
			if err == nil {
				t.Errorf("%s: no error", in)
			}
			continue
		}
		if err != nil || got.Format(time.RFC3339Nano) != want {
			t.Errorf("%s: got %v, %v", in, got.Format(time.RFC3339Nano), err)
		}
	}
}

func TestChecker(t *testing.T) {
	f := newFixture(t, testpki.P256(t), testpki.P256(t))
	var requests atomic.Int32
	var mode atomic.Value
	mode.Store("good")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		if r.Method != http.MethodPost || r.Header.Get("Content-Type") != "application/ocsp-request" {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		switch mode.Load() {
		case "500":
			http.Error(w, "down", http.StatusInternalServerError)
			return
		case "slow":
			time.Sleep(300 * time.Millisecond)
		case "garbage":
			w.Write([]byte("garbage"))
			return
		}
		var body strings.Builder
		buf := make([]byte, 4096)
		n, _ := r.Body.Read(buf)
		body.Write(buf[:n])
		req, err := ParseRequest([]byte(body.String()))
		if err != nil || !req.CertIDs[0].Matches(f.leaf, f.ca) {
			der, _ := CreateResponse(ResponseTemplate{Status: Unauthorized}, nil, nil)
			w.Write(der)
			return
		}
		tmpl := f.good(t)
		tmpl.ProducedAt = getClock()
		tmpl.Responses[0].ThisUpdate = getClock()
		w.Header().Set("Content-Type", "application/ocsp-response")
		w.Write(f.create(t, tmpl))
	}))
	defer srv.Close()

	c := &Checker{GracePeriod: time.Minute, Timeout: 100 * time.Millisecond, Time: getClock}
	responders := []*x509.Certificate{f.responder}
	ctx := context.Background()
	setClock(now)
	if _, sr, err := c.Check(ctx, f.leaf, f.ca, srv.URL, responders); err != nil || sr.Status != Good {
		t.Fatalf("first check: %v", err)
	}
	setClock(now.Add(30 * time.Second))
	if _, _, err := c.Check(ctx, f.leaf, f.ca, srv.URL, responders); err != nil || requests.Load() != 1 {
		t.Fatalf("within grace period: %v, %d requests", err, requests.Load())
	}
	setClock(now.Add(61 * time.Second))
	if _, _, err := c.Check(ctx, f.leaf, f.ca, srv.URL, responders); err != nil || requests.Load() != 2 {
		t.Fatalf("after grace period: %v, %d requests", err, requests.Load())
	}
	c.Flush()
	for m, want := range map[string]error{"500": ErrNotAvailable, "slow": ErrNotAvailable, "garbage": ErrCheckRevocation} {
		mode.Store(m)
		if _, _, err := c.Check(ctx, f.leaf, f.ca, srv.URL, responders); !errors.Is(err, want) {
			t.Errorf("%s: got %v, want %v", m, err, want)
		}
	}
	mode.Store("good")
	if _, _, err := c.Check(ctx, f.leaf, f.ca, srv.URL, nil); !errors.Is(err, ErrCertMissing) {
		t.Errorf("no responders: got %v", err)
	}
	if _, _, err := c.Check(ctx, f.leaf, f.ca, "", responders); !errors.Is(err, ErrCheckRevocation) {
		t.Errorf("no URL: got %v", err)
	}
}

var clock atomic.Int64

func setClock(t time.Time) { clock.Store(t.UnixNano()) }
func getClock() time.Time  { return time.Unix(0, clock.Load()).UTC() }
