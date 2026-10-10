//go:build ivory

package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/DominicBreuker/ivory/brainpool"
	"github.com/DominicBreuker/ivory/internal/testpki"
	"github.com/DominicBreuker/ivory/internal/tsltest"
	"github.com/DominicBreuker/ivory/ocsp"
	"github.com/DominicBreuker/ivory/ti"
	"github.com/DominicBreuker/ivory/tlsutil"
	"github.com/DominicBreuker/ivory/tsl"
	"github.com/DominicBreuker/ivory/x509util"
)

const policyCMTLSCS = "1.2.276.0.76.4.175" // C.CM.TLS-CS

func writePEM(t *testing.T, dir, name, typ string, der []byte) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: typ, Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// TestFachdienst runs the example server with a TSL signed with
// brainpoolP256r1, a Brainpool CA and OCSP signer, and Brainpool clients.
func TestFachdienst(t *testing.T) {
	bp := func() *brainpool.PrivateKey { return testpki.Brainpool(t, brainpool.P256r1()) }
	anchorKey, signerKey, caKey, ocspKey := bp(), bp(), bp(), bp()
	anchor := testpki.Issue(t, testpki.CA("GEM.TSL-CA-TEST"), anchorKey, nil, anchorKey)
	signer := testpki.Issue(t, &x509.Certificate{
		Subject:            pkix.Name{CommonName: "TSL Signing Unit TEST"},
		KeyUsage:           x509.KeyUsageContentCommitment,
		UnknownExtKeyUsage: []asn1.ObjectIdentifier{tsl.OIDTSLSigning},
	}, signerKey, anchor, anchorKey)
	ca := testpki.Issue(t, testpki.CA("GEM.KOMP-CA-TEST"), caKey, nil, caKey)
	ocspSigner := testpki.Issue(t, testpki.EE("OCSP Signer", x509.KeyUsageDigitalSignature, x509.ExtKeyUsageOCSPSigning), ocspKey, ca, caKey)
	client := func(policy string) (tls.Certificate, *x509.Certificate) {
		key := bp()
		tmpl := testpki.EE("clientmodul", x509.KeyUsageDigitalSignature, x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth)
		oid, _ := x509.ParseOID(policy)
		tmpl.Policies = []x509.OID{oid}
		c := testpki.Issue(t, tmpl, key, ca, caKey)
		tc, err := tlsutil.Certificate([][]byte{c.Raw}, key)
		if err != nil {
			t.Fatal(err)
		}
		return tc, c
	}
	good, goodCert := client(policyCMTLSCS)
	revoked, revokedCert := client(policyCMTLSCS)
	wrongType, _ := client("1.2.276.0.76.4.174")

	var ocspRequests atomic.Int32
	responder := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ocspRequests.Add(1)
		body, _ := io.ReadAll(r.Body)
		req, err := ocsp.ParseRequest(body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		now := time.Now()
		sr := ocsp.SingleResponse{CertID: req.CertIDs[0], Status: ocsp.Good, ThisUpdate: now}
		switch {
		case req.CertIDs[0].Matches(goodCert, ca):
			sr.CertHash = ocsp.NewCertHash(goodCert)
		case req.CertIDs[0].Matches(revokedCert, ca):
			sr.Status, sr.RevokedAt = ocsp.Revoked, now.Add(-time.Hour)
		default:
			sr.Status = ocsp.Unknown
		}
		der, err := ocsp.CreateResponse(ocsp.ResponseTemplate{ProducedAt: now, Responses: []ocsp.SingleResponse{sr}}, ocspSigner, ocspKey)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Write(der)
	}))
	defer responder.Close()

	dir := t.TempDir()
	xml := tsltest.XML(10001, time.Now().Add(24*time.Hour), "http://127.0.0.1:1/tsl.xml", "http://127.0.0.1:1/tsl-backup.xml",
		tsltest.Service{Type: tsl.TypeCA, Certs: []*x509.Certificate{ca}, SupplyPoints: []string{responder.URL}, ExtensionOIDs: []string{policyCMTLSCS}, Name: "CA"},
		tsltest.Service{Type: tsl.TypeOCSP, Certs: []*x509.Certificate{ocspSigner}, Name: "OCSP"})
	tslFile := filepath.Join(dir, "tsl.xml")
	if err := os.WriteFile(tslFile, tsltest.Sign(t, xml, signer, signerKey), 0o600); err != nil {
		t.Fatal(err)
	}
	serverKey := bp()
	serverCert := testpki.Issue(t, testpki.EE("fachdienst.example", x509.KeyUsageDigitalSignature, x509.ExtKeyUsageServerAuth), serverKey, ca, caKey)
	keyDER, err := x509util.MarshalPKCS8PrivateKey(serverKey)
	if err != nil {
		t.Fatal(err)
	}
	o := options{
		certFile:    writePEM(t, dir, "server.pem", "CERTIFICATE", serverCert.Raw),
		keyFile:     writePEM(t, dir, "server.key", "PRIVATE KEY", keyDER),
		anchorFile:  writePEM(t, dir, "anchor.pem", "CERTIFICATE", anchor.Raw),
		tslSource:   tslFile,
		policies:    policyCMTLSCS,
		tslInterval: time.Hour,
		ocspGrace:   time.Minute,
		ocspTimeout: 5 * time.Second,
	}
	s, err := newServer(o, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	if err := s.init(context.Background(), o.tslSource, o.anchorFile); err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go s.serve(ln)

	dial := func(cert tls.Certificate) (string, error) {
		cfg := ti.ClientConfig(&cert, &ti.Verifier{CAs: []*x509.Certificate{ca}})
		conn, err := tls.Dial("tcp", ln.Addr().String(), cfg)
		if err != nil {
			return "", err
		}
		defer conn.Close()
		line, err := io.ReadAll(conn)
		return string(line), err
	}
	if line, err := dial(good); err != nil || !strings.HasPrefix(line, "hello clientmodul") {
		t.Errorf("good client: %q, %v", line, err)
	}
	if _, err := dial(good); err != nil || ocspRequests.Load() != 1 {
		t.Errorf("second connection: %v, %d OCSP requests (want 1: grace period)", err, ocspRequests.Load())
	}
	if _, err := dial(revoked); err == nil {
		t.Error("revoked client accepted")
	}
	if _, err := dial(wrongType); err == nil {
		t.Error("client with the wrong certificate type accepted")
	}
}
