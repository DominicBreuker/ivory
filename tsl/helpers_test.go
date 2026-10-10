//go:build ivory

package tsl

import (
	"crypto"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"testing"
	"time"

	"github.com/DominicBreuker/ivory/brainpool"
	"github.com/DominicBreuker/ivory/internal/testpki"
	"github.com/DominicBreuker/ivory/internal/tsltest"
	"github.com/DominicBreuker/ivory/internal/xmldsig"
)

var testNow = time.Date(2030, 1, 1, 12, 0, 0, 0, time.UTC)

type testService = tsltest.Service

func unsignedTSL(seq int, next time.Time, services ...testService) string {
	return tsltest.XML(seq, next, "http://tsl.example/tsl.xml", "http://tsl-backup.example/tsl.xml", services...)
}

// signTSL adds an enveloped signature to the unsigned TSL xml, made
// with key, the key of signer, the way the TSL service signs.
func signTSL(t testing.TB, unsigned string, signer *x509.Certificate, key crypto.Signer) []byte {
	t.Helper()
	data, err := xmldsig.SignEnveloped([]byte(unsigned), signer, key)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

// pki is a test PKI: a TSL trust anchor and signer, a CA with an OCSP
// signer, and an end-entity certificate.
type pki struct {
	anchor, signer, ca, ocspSigner, leaf *x509.Certificate
	anchorKey, signerKey, caKey, ocspKey crypto.Signer
}

var (
	oidTypeSMCBAut = "1.2.276.0.76.4.77" // oid_smc_b_aut
	oidTypeHBAAut  = "1.2.276.0.76.4.75" // oid_hba_aut
)

func newPKI(t testing.TB, signerKey crypto.Signer) *pki {
	t.Helper()
	p := &pki{
		anchorKey: testpki.Brainpool(t, brainpool.P256r1()),
		signerKey: signerKey,
		caKey:     testpki.Brainpool(t, brainpool.P256r1()),
		ocspKey:   testpki.Brainpool(t, brainpool.P256r1()),
	}
	p.anchor = testpki.Issue(t, testpki.CA("GEM.TSL-CA-TEST"), p.anchorKey, nil, p.anchorKey)
	p.signer = testpki.Issue(t, signerTemplate(), signerKey, p.anchor, p.anchorKey)
	p.ca = testpki.Issue(t, testpki.CA("GEM.SMCB-CA-TEST"), p.caKey, nil, p.caKey)
	p.ocspSigner = testpki.Issue(t, testpki.EE("OCSP Signer", x509.KeyUsageDigitalSignature, x509.ExtKeyUsageOCSPSigning), p.ocspKey, p.ca, p.caKey)
	p.leaf = p.issueLeaf(t, oidTypeSMCBAut, time.Time{})
	return p
}

func (p *pki) issueLeaf(t testing.TB, policy string, notBefore time.Time) *x509.Certificate {
	t.Helper()
	tmpl := testpki.EE("leaf", x509.KeyUsageDigitalSignature, x509.ExtKeyUsageClientAuth)
	oid, err := x509.ParseOID(policy)
	if err != nil {
		t.Fatal(err)
	}
	tmpl.Policies = []x509.OID{oid}
	if !notBefore.IsZero() {
		tmpl.NotBefore, tmpl.NotAfter = notBefore, testpki.End
	}
	return testpki.Issue(t, tmpl, testpki.P256(t), p.ca, p.caKey)
}

func signerTemplate() *x509.Certificate {
	return &x509.Certificate{
		Subject:               pkix.Name{CommonName: "TSL Signing Unit TEST"},
		KeyUsage:              x509.KeyUsageContentCommitment,
		UnknownExtKeyUsage:    []asn1.ObjectIdentifier{OIDTSLSigning},
		BasicConstraintsValid: true,
	}
}

// services returns the CA and OCSP services of p with responder url.
func (p *pki) services(url string) []testService {
	return []testService{
		{Type: TypeCA, Certs: []*x509.Certificate{p.ca}, SupplyPoints: []string{url}, ExtensionOIDs: []string{oidTypeSMCBAut}, Name: "CA"},
		{Type: TypeOCSP, Certs: []*x509.Certificate{p.ocspSigner}, Name: "OCSP"},
	}
}

func (p *pki) signedTSL(t testing.TB, seq int, services ...testService) []byte {
	t.Helper()
	return signTSL(t, unsignedTSL(seq, testNow.Add(30*24*time.Hour), services...), p.signer, p.signerKey)
}
