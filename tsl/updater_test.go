//go:build ivory

package tsl

import (
	"context"
	"crypto"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/DominicBreuker/ivory/brainpool"
	"github.com/DominicBreuker/ivory/internal/testpki"
	"github.com/DominicBreuker/ivory/internal/tsltest"
	"github.com/DominicBreuker/ivory/ocsp"
)

// tslServer serves a TSL and its hash at /p/tsl.xml (primary) and
// /b/tsl.xml (backup), and answers OCSP requests at /ocsp.
type tslServer struct {
	*httptest.Server
	mu        sync.Mutex
	tsl       []byte
	down      map[string]bool // "p", "b": the address answers 500
	requests  map[string]int  // path → count
	status    ocsp.CertStatus
	certHash  *ocsp.CertHash
	responder *x509.Certificate
	key       crypto.Signer
	now       func() time.Time
}

func newTSLServer(t *testing.T, responder *x509.Certificate, key crypto.Signer) *tslServer {
	s := &tslServer{down: map[string]bool{}, requests: map[string]int{}, responder: responder, key: key, now: func() time.Time { return testNow }}
	s.Server = httptest.NewServer(http.HandlerFunc(s.handle))
	t.Cleanup(s.Close)
	return s
}

func (s *tslServer) set(tsl []byte) {
	s.mu.Lock()
	s.tsl = tsl
	s.mu.Unlock()
}

func (s *tslServer) count(path string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.requests[path]
}

func (s *tslServer) handle(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	s.requests[r.URL.Path]++
	tsl, down := s.tsl, s.down[strings.Split(r.URL.Path, "/")[1]]
	s.mu.Unlock()
	if r.URL.Path == "/ocsp" {
		s.answerOCSP(w, r)
		return
	}
	if down || tsl == nil {
		http.Error(w, "down", http.StatusInternalServerError)
		return
	}
	switch {
	case strings.HasSuffix(r.URL.Path, ".sha2"):
		h := sha256.Sum256(tsl)
		io.WriteString(w, hex.EncodeToString(h[:]))
	default:
		w.Write(tsl)
	}
}

func (s *tslServer) answerOCSP(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	req, err := ocsp.ParseRequest(body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	s.mu.Lock()
	sr := ocsp.SingleResponse{CertID: req.CertIDs[0], Status: s.status, ThisUpdate: s.now(), RevokedAt: s.now().Add(-time.Hour), CertHash: s.certHash}
	s.mu.Unlock()
	tmpl := ocsp.ResponseTemplate{ProducedAt: s.now(), Responses: []ocsp.SingleResponse{sr}}
	der, err := ocsp.CreateResponse(tmpl, s.responder, s.key)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Write(der)
}

func TestUpdater(t *testing.T) {
	p := newPKI(t, testpki.Brainpool(t, brainpool.P256r1()))
	srv := newTSLServer(t, p.ocspSigner, p.ocspKey)
	// The responder answers for the TSL signer.
	srv.certHash = ocsp.NewCertHash(p.signer)

	// The TSL lists the anchor (with the OCSP address for the signer),
	// the CA and the OCSP signer.
	services := func() []testService {
		return append(p.services(srv.URL+"/ocsp"),
			testService{Type: TypeCA, Certs: []*x509.Certificate{p.anchor}, SupplyPoints: []string{srv.URL + "/ocsp"}, Name: "TSL-CA"})
	}
	build := func(seq int, svcs ...testService) []byte {
		return tsltest.Sign(t, tsltest.XML(seq, testNow.Add(24*time.Hour), srv.URL+"/p/tsl.xml?seq=1", srv.URL+"/b/tsl.xml?seq=1", svcs...), p.signer, p.signerKey)
	}
	now := testNow
	u := &Updater{
		OCSP: &ocsp.Checker{Time: func() time.Time { return now }},
		Time: func() time.Time { return now },
	}
	ctx := context.Background()
	first := build(10001, services()...)
	if err := u.Init(first, p.anchor); err != nil {
		t.Fatal(err)
	}
	if u.Current().SequenceNumber != 10001 {
		t.Fatal("not imported")
	}

	// Same TSL: only the hash is fetched.
	srv.set(first)
	if changed, err := u.Update(ctx); err != nil || changed || srv.count("/p/tsl.xml") != 0 || srv.count("/p/tsl.sha2") != 1 {
		t.Fatalf("same TSL: %v %v, %d downloads", changed, err, srv.count("/p/tsl.xml"))
	}

	// A newer TSL is downloaded and imported after the signer's OCSP check.
	srv.set(build(10002, services()...))
	if changed, err := u.Update(ctx); err != nil || !changed || u.Current().SequenceNumber != 10002 || srv.count("/ocsp") != 1 {
		t.Fatalf("new TSL: %v %v, %d OCSP requests", changed, err, srv.count("/ocsp"))
	}

	// Older or same-number TSLs are refused (TUC_PKI_019 step 6b).
	srv.set(build(10001, services()...))
	if _, err := u.Update(ctx); !errors.Is(err, ErrID) {
		t.Errorf("older TSL: %v", err)
	}

	// The signer is revoked: the TSL is refused.
	srv.mu.Lock()
	srv.status = ocsp.Revoked
	srv.mu.Unlock()
	srv.set(build(10003, services()...))
	if _, err := u.Update(ctx); !errors.Is(err, ocsp.ErrRevoked) || u.Current().SequenceNumber != 10002 {
		t.Errorf("revoked signer: %v", err)
	}
	srv.mu.Lock()
	srv.status = ocsp.Good
	srv.mu.Unlock()

	// Primary down: the backup delivers, after four attempts at the
	// primary.
	srv.mu.Lock()
	srv.down["p"] = true
	srv.mu.Unlock()
	before := srv.count("/p/tsl.xml")
	if changed, err := u.Update(ctx); err != nil || !changed || u.Current().SequenceNumber != 10003 {
		t.Errorf("backup: %v %v", changed, err)
	}
	if n := srv.count("/p/tsl.xml") - before; n != 4 {
		t.Errorf("%d attempts at the primary address", n)
	}

	// Both down: TSL_DOWNLOAD_ERROR, and the trust space stays.
	srv.mu.Lock()
	srv.down["b"] = true
	srv.mu.Unlock()
	srv.set(build(10004, services()...))
	if _, err := u.Update(ctx); !errors.Is(err, ErrDownload) || u.Current().SequenceNumber != 10003 {
		t.Errorf("all down: %v", err)
	}

	// After NextUpdate (and no grace), there is no trust space.
	now = testNow.Add(25 * time.Hour)
	if u.Current() != nil {
		t.Error("expired TSL still current")
	}
	if _, err := u.Update(ctx); !errors.Is(err, ErrNoTrustSpace) {
		t.Errorf("expired: %v", err)
	}
	u.Grace = 2 * time.Hour
	if u.Current() == nil {
		t.Error("TSL within grace period not current")
	}
}

// TestUpdaterTrustAnchorChange: a TSL announces a new trust anchor; TSLs
// signed under it are refused before its StatusStartingTime and accepted
// after (TUC_PKI_013).
func TestUpdaterTrustAnchorChange(t *testing.T) {
	p := newPKI(t, testpki.Brainpool(t, brainpool.P256r1()))
	newAnchorKey := testpki.Brainpool(t, brainpool.P256r1())
	newAnchor := testpki.Issue(t, testpki.CA("GEM.TSL-CA-NEW"), newAnchorKey, nil, newAnchorKey)
	newSignerKey := testpki.Brainpool(t, brainpool.P256r1())
	newSigner := testpki.Issue(t, signerTemplate(), newSignerKey, newAnchor, newAnchorKey)
	start := testNow.Add(time.Hour)

	now := testNow
	u := &Updater{Time: func() time.Time { return now }} // offline
	ta := testService{Type: TypeTSLServiceCertChg, Certs: []*x509.Certificate{newAnchor}, Start: start, Name: "TA"}
	xml := func(seq int, svcs ...testService) string {
		return tsltest.XML(seq, testNow.Add(48*time.Hour), "http://tsl.example/tsl.xml", "http://tsl-backup.example/tsl.xml", svcs...)
	}
	if err := u.Init(tsltest.Sign(t, xml(10001, ta), p.signer, p.signerKey), p.anchor); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	underNew := tsltest.Sign(t, xml(10002), newSigner, newSignerKey)
	if _, err := u.Import(ctx, underNew); !errors.Is(err, ErrCertSignature) {
		t.Errorf("before StatusStartingTime: %v", err)
	}
	now = start.Add(time.Minute)
	if changed, err := u.Import(ctx, underNew); err != nil || !changed {
		t.Fatalf("after StatusStartingTime: %v", err)
	}
	if !u.TrustAnchor().Equal(newAnchor) {
		t.Error("anchor not activated")
	}
	// The old anchor no longer counts.
	if _, err := u.Import(ctx, tsltest.Sign(t, xml(10003), p.signer, p.signerKey)); !errors.Is(err, ErrCertSignature) {
		t.Errorf("old anchor: %v", err)
	}
}
