//go:build ivory

package tsl

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/DominicBreuker/ivory/brainpool"
	"github.com/DominicBreuker/ivory/internal/testpki"
	"github.com/DominicBreuker/ivory/ocsp"
)

func parseAndVerify(t testing.TB, data []byte, anchors ...*x509.Certificate) (*TSL, error) {
	t.Helper()
	l, err := Parse(data)
	if err != nil {
		return nil, err
	}
	_, err = l.Verify(VerifyOptions{TrustAnchors: anchors, Time: testNow})
	return l, err
}

func TestVerifySignerKeys(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	for name, key := range map[string]crypto.Signer{
		"brainpoolP256r1": testpki.Brainpool(t, brainpool.P256r1()),
		"P-256":           testpki.P256(t),
		"RSA":             rsaKey,
	} {
		t.Run(name, func(t *testing.T) {
			p := newPKI(t, key)
			data := p.signedTSL(t, 10001, p.services("http://ocsp.example/ocsp")...)
			l, err := parseAndVerify(t, data, p.anchor)
			if err != nil {
				t.Fatal(err)
			}
			if l.SequenceNumber != 10001 || l.ID != "ID10001" || len(l.Services) != 2 {
				t.Errorf("parsed %+v", l)
			}
			if len(l.CAs()) != 1 || !l.CAs()[0].Equal(p.ca) || len(l.OCSPResponders()) != 1 {
				t.Error("CAs or OCSP responders wrong")
			}
			if l.PrimaryLocations[0] != "http://tsl.example/tsl.xml" || l.BackupLocations[0] != "http://tsl-backup.example/tsl.xml" {
				t.Errorf("locations %v %v", l.PrimaryLocations, l.BackupLocations)
			}
		})
	}
}

func TestVerifyTampered(t *testing.T) {
	p := newPKI(t, testpki.Brainpool(t, brainpool.P256r1()))
	data := string(p.signedTSL(t, 10001, p.services("http://ocsp.example/ocsp")...))
	for name, mod := range map[string]func(string) string{
		"service status": func(s string) string {
			return strings.Replace(s, StatusInAccord, StatusRevoked, 1)
		},
		"OCSP address": func(s string) string {
			return strings.Replace(s, "http://ocsp.example/ocsp", "http://evil.example/ocsp", 1)
		},
		"signed properties": func(s string) string {
			return strings.Replace(s, "2030-01-01T00:00:00Z", "2030-01-02T00:00:00Z", 1)
		},
		"signature value": func(s string) string {
			i := strings.Index(s, "<ds:SignatureValue>") + len("<ds:SignatureValue>")
			c := byte('A')
			if s[i] == 'A' {
				c = 'B'
			}
			return s[:i] + string(c) + s[i+1:]
		},
		"reference URI": func(s string) string { return strings.Replace(s, `URI=""`, `URI="#ID10001"`, 1) },
		"no enveloped transform": func(s string) string {
			return strings.Replace(s, `<ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/>`, "", 1)
		},
		"second whole-document reference": func(s string) string {
			i := strings.Index(s, "<ds:Reference Id=\"reference-document\"")
			j := strings.Index(s, "</ds:Reference>") + len("</ds:Reference>")
			return s[:j] + strings.Replace(s[i:j], `Id="reference-document" `, "", 1) + s[j:]
		},
		"comment canonicalization": func(s string) string {
			return strings.Replace(s, "ivory TSP", "ivory<!-- c --> TSP", 1)
		},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := parseAndVerify(t, []byte(mod(data)), p.anchor)
			if name == "comment canonicalization" {
				// Comments are not part of the canonical form: the
				// signature stays valid, and the parsed text skips them.
				if err != nil {
					t.Fatal(err)
				}
				l, _ := Parse([]byte(mod(data)))
				if l.Services[0].Provider != "ivory TSP" {
					t.Errorf("provider %q", l.Services[0].Provider)
				}
				return
			}
			if !errors.Is(err, ErrSignature) {
				t.Errorf("got %v, want ErrSignature", err)
			}
		})
	}
}

func TestVerifySigner(t *testing.T) {
	anchorKey := testpki.Brainpool(t, brainpool.P256r1())
	anchor := testpki.Issue(t, testpki.CA("GEM.TSL-CA-TEST"), anchorKey, nil, anchorKey)
	otherKey := testpki.Brainpool(t, brainpool.P256r1())
	other := testpki.Issue(t, testpki.CA("GEM.TSL-CA-TEST"), otherKey, nil, otherKey)
	for _, tc := range []struct {
		name   string
		modify func(*x509.Certificate)
		anchor *x509.Certificate
		want   error
	}{
		{name: "valid", anchor: anchor},
		{name: "other anchor", anchor: other, want: ErrCertSignature},
		{name: "no nonRepudiation", modify: func(c *x509.Certificate) { c.KeyUsage = x509.KeyUsageDigitalSignature }, anchor: anchor, want: ErrKeyUsage},
		{name: "no tslSigning", modify: func(c *x509.Certificate) { c.UnknownExtKeyUsage = nil }, anchor: anchor, want: ErrExtKeyUsage},
		{name: "expired", modify: func(c *x509.Certificate) {
			c.NotBefore, c.NotAfter = testNow.Add(-48*time.Hour), testNow.Add(-24*time.Hour)
		}, anchor: anchor, want: ErrCertValidity},
		{name: "not yet valid", modify: func(c *x509.Certificate) {
			c.NotBefore, c.NotAfter = testNow.Add(24*time.Hour), testNow.Add(48*time.Hour)
		}, anchor: anchor, want: ErrCertValidity},
	} {
		t.Run(tc.name, func(t *testing.T) {
			key := testpki.Brainpool(t, brainpool.P256r1())
			tmpl := signerTemplate()
			if tc.modify != nil {
				tc.modify(tmpl)
			}
			signer := testpki.Issue(t, tmpl, key, anchor, anchorKey)
			data := signTSL(t, unsignedTSL(10001, testNow.Add(time.Hour)), signer, key)
			_, err := parseAndVerify(t, data, tc.anchor)
			if tc.want == nil && err != nil || tc.want != nil && !errors.Is(err, tc.want) {
				t.Errorf("got %v, want %v", err, tc.want)
			}
		})
	}
}

func TestSchema(t *testing.T) {
	base := unsignedTSL(10001, testNow, testService{Type: TypeCA, Name: "CA"})
	if _, err := Parse([]byte(base)); err != nil {
		t.Fatalf("base: %v", err)
	}
	for name, mod := range map[string]func(string) string{
		"foreign element": func(s string) string {
			return strings.Replace(s, "</TrustServiceProviderList>", "<ThisDoesNotBelongToETSI>x</ThisDoesNotBelongToETSI></TrustServiceProviderList>", 1)
		},
		"wrong namespace": func(s string) string {
			return strings.Replace(s, `xmlns="http://uri.etsi.org/02231/v2#"`, `xmlns="http://invalidnamespace.gematik.net/02231/v2#"`, 1)
		},
		"missing element": func(s string) string {
			return strings.Replace(s, "<HistoricalInformationPeriod>0</HistoricalInformationPeriod>", "", 1)
		},
		"order": func(s string) string {
			return strings.Replace(strings.Replace(s, "<TSLVersionIdentifier>3</TSLVersionIdentifier>", "", 1),
				"<TSLType>", "<TSLVersionIdentifier>3</TSLVersionIdentifier><TSLType>", 1)
		},
		"bad dateTime": func(s string) string {
			return strings.Replace(s, "<ListIssueDateTime>", "<ListIssueDateTime>yesterday ", 1)
		},
		"bad sequence number": func(s string) string {
			return strings.Replace(s, "<TSLSequenceNumber>10001", "<TSLSequenceNumber>-10001", 1)
		},
		"missing xml:lang": func(s string) string {
			return strings.Replace(s, `<Name xml:lang="DE">ivory test</Name>`, `<Name>ivory test</Name>`, 1)
		},
		"unknown attribute": func(s string) string {
			return strings.Replace(s, "<SchemeInformation>", `<SchemeInformation foo="bar">`, 1)
		},
		"bad TSLTag": func(s string) string {
			return strings.Replace(s, `TSLTag="http://uri.etsi.org/02231/TSLTag"`, `TSLTag="x"`, 1)
		},
		"text in element content": func(s string) string {
			return strings.Replace(s, "<SchemeInformation>", "<SchemeInformation>text", 1)
		},
		"two DigitalId choices": func(s string) string {
			return strings.Replace(s, "<ServiceDigitalIdentity>", "<ServiceDigitalIdentity><DigitalId><X509SKI>AAAA</X509SKI><X509SKI>AAAA</X509SKI></DigitalId>", 1)
		},
		"not well-formed": func(s string) string { return s[:len(s)-5] },
		"DTD": func(s string) string {
			return strings.Replace(s, "<TrustServiceStatusList ", "<!DOCTYPE x [<!ENTITY a \"b\">]><TrustServiceStatusList ", 1)
		},
		"undeclared prefix": func(s string) string {
			return strings.Replace(s, "<SchemeInformation>", "<SchemeInformation><x:y/>", 1)
		},
		"latin-1": func(s string) string { return strings.Replace(s, `encoding="UTF-8"`, `encoding="ISO-8859-1"`, 1) },
		"newline in attribute": func(s string) string {
			return strings.Replace(s, `xml:lang="DE">ivory test<`, "xml:lang=\"D\nE\">ivory test<", 1)
		},
		"duplicate Id": func(s string) string {
			return strings.Replace(s, "<SchemeInformation>", `<SchemeInformation><x Id="ID10001" xmlns=""/>`, 1)
		},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := Parse([]byte(mod(base))); err == nil {
				t.Error("no error")
			}
		})
	}
}

func TestServices(t *testing.T) {
	p := newPKI(t, testpki.Brainpool(t, brainpool.P256r1()))
	unspecKey := testpki.P256(t)
	unspec := testpki.Issue(t, testpki.CA("unspecified"), unspecKey, nil, unspecKey)
	revokedKey := testpki.P256(t)
	revoked := testpki.Issue(t, testpki.CA("revoked CA"), revokedKey, nil, revokedKey)
	newAnchorKey := testpki.Brainpool(t, brainpool.P256r1())
	newAnchor := testpki.Issue(t, testpki.CA("GEM.TSL-CA-NEW"), newAnchorKey, nil, newAnchorKey)
	ta := testService{Type: TypeTSLServiceCertChg, Certs: []*x509.Certificate{newAnchor}, Start: testNow.Add(time.Hour), Name: "TA"}
	svcs := append(p.services("http://ocsp.example/ocsp"),
		testService{Type: TypeUnspecified, Certs: []*x509.Certificate{unspec}},
		testService{Type: TypeCA, Status: StatusRevoked, Certs: []*x509.Certificate{revoked}},
		ta)
	l, err := parseAndVerify(t, p.signedTSL(t, 10002, svcs...), p.anchor)
	if err != nil {
		t.Fatal(err)
	}
	cas := l.CAs()
	if len(cas) != 2 || !cas[0].Equal(p.ca) || !cas[1].Equal(revoked) {
		t.Errorf("CAs: %d", len(cas))
	}
	s, ca, err := l.IssuerService(p.leaf)
	if err != nil || !ca.Equal(p.ca) || s.OCSPLocation() != "http://ocsp.example/ocsp" {
		t.Errorf("IssuerService: %v", err)
	}
	stranger := testpki.Issue(t, testpki.EE("x", x509.KeyUsageDigitalSignature), testpki.P256(t), unspec, unspecKey)
	if _, _, err := l.IssuerService(stranger); !errors.Is(err, ErrCAMissing) {
		t.Errorf("unspecified CA: %v", err)
	}
	a, start, err := l.AnnouncedTrustAnchor()
	if err != nil || !a.Equal(newAnchor) || !start.Equal(testNow.Add(time.Hour)) {
		t.Errorf("AnnouncedTrustAnchor: %v", err)
	}
	two, _ := parseAndVerify(t, p.signedTSL(t, 10003, ta, ta), p.anchor)
	if _, _, err := two.AnnouncedTrustAnchor(); !errors.Is(err, ErrMultipleTrustAnchors) {
		t.Errorf("two anchors: %v", err)
	}
	early := ta
	early.Start = testpki.Start.Add(-time.Hour)
	l3, _ := parseAndVerify(t, p.signedTSL(t, 10004, early), p.anchor)
	if _, _, err := l3.AnnouncedTrustAnchor(); !errors.Is(err, ErrCertValidity) {
		t.Errorf("anchor not valid at StatusStartingTime: %v", err)
	}
	if l.Expired(testNow, 0) || !l.Expired(testNow.Add(31*24*time.Hour), 0) || l.Expired(testNow.Add(31*24*time.Hour), 48*time.Hour) {
		t.Error("Expired")
	}
}

// responder is an OCSP responder for a pki.
func (p *pki) responder(t testing.TB, mod func(*ocsp.ResponseTemplate)) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		req, err := ocsp.ParseRequest(body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		sr := ocsp.SingleResponse{CertID: req.CertIDs[0], Status: ocsp.Good, ThisUpdate: testNow, CertHash: ocsp.NewCertHash(p.leaf)}
		tmpl := ocsp.ResponseTemplate{ProducedAt: testNow, Responses: []ocsp.SingleResponse{sr}}
		if mod != nil {
			mod(&tmpl)
		}
		der, err := ocsp.CreateResponse(tmpl, p.ocspSigner, p.ocspKey)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Write(der)
	}))
}

func TestStatus(t *testing.T) {
	p := newPKI(t, testpki.Brainpool(t, brainpool.P256r1()))
	good := p.responder(t, nil)
	defer good.Close()
	revoked := p.responder(t, func(r *ocsp.ResponseTemplate) {
		r.Responses[0].Status, r.Responses[0].RevokedAt = ocsp.Revoked, testNow.Add(-time.Hour)
	})
	defer revoked.Close()
	down := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "down", http.StatusInternalServerError)
	}))
	defer down.Close()

	checker := &ocsp.Checker{Time: func() time.Time { return testNow }}
	smcb, _ := x509.ParseOID(oidTypeSMCBAut)
	for _, tc := range []struct {
		name     string
		url      string
		status   string
		start    time.Time
		leaf     *x509.Certificate
		policies []x509.OID
		tolerate bool
		want     error
	}{
		{name: "good", url: good.URL},
		{name: "good with PolicyList", url: good.URL, policies: []x509.OID{smcb}},
		{name: "revoked", url: revoked.URL, want: ocsp.ErrRevoked},
		{name: "responder down", url: down.URL, want: ocsp.ErrNotAvailable},
		{name: "responder down, tolerated", url: down.URL, tolerate: true},
		{name: "no supply point", url: "", want: ocsp.ErrCheckRevocation},
		{name: "CA revoked later", url: good.URL, status: StatusRevoked, start: testpki.Start.Add(time.Hour)},
		{name: "CA revoked before issue", url: good.URL, status: StatusRevoked, start: testpki.Start.Add(-time.Hour), want: ErrCARevoked},
		{name: "type not authorized", url: good.URL, leaf: p.issueLeaf(t, oidTypeHBAAut, time.Time{}), want: ErrCertTypeNotAuthorized},
	} {
		t.Run(tc.name, func(t *testing.T) {
			svcs := p.services(tc.url)
			if tc.url == "" {
				svcs[0].SupplyPoints = nil
			}
			svcs[0].Status, svcs[0].Start = tc.status, tc.start
			l, err := parseAndVerify(t, p.signedTSL(t, 10001, svcs...), p.anchor)
			if err != nil {
				t.Fatal(err)
			}
			leaf := p.leaf
			if tc.leaf != nil {
				leaf = tc.leaf
			}
			var warned error
			check := l.Status(StatusOptions{
				Policies: tc.policies, OCSP: checker, TolerateOCSPFailure: tc.tolerate,
				OnWarning: func(err error) { warned = err }, Context: context.Background(),
			})
			err = check(leaf, p.ca)
			if tc.want == nil && err != nil || tc.want != nil && !errors.Is(err, tc.want) {
				t.Errorf("got %v, want %v", err, tc.want)
			}
			if tc.tolerate && warned == nil {
				t.Error("no warning")
			}
		})
	}
}
