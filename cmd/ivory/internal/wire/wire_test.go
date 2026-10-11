package wire

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestHelloRoundTrip(t *testing.T) {
	spec := &HelloSpec{
		Version:              VersionTLS12,
		CipherSuites:         []CipherSuite{0xc02b, 0x1301},
		ServerName:           "kt.example",
		SupportedVersions:    []Version{VersionTLS13, VersionTLS12},
		SupportedGroups:      []Group{0x001f, 0x001a, 0x0017},
		SignatureAlgorithms:  []SignatureScheme{0x081a, 0x0403},
		EmptyKeyShare:        true,
		ALPN:                 []string{"h2", "http/1.1"},
		ECPointFormats:       true,
		ExtendedMasterSecret: true,
		RenegotiationInfo:    true,
		SessionTicket:        true,
		StatusRequest:        true,
		PSKModes:             true,
	}
	recs := SplitRecords(spec.Bytes())
	if len(recs) != 1 || len(recs[0].Messages) != 1 || recs[0].Messages[0].Type != TypeClientHello {
		t.Fatalf("records: %+v", recs)
	}
	ch, err := ParseClientHello(recs[0].Messages[0].Body)
	if err != nil {
		t.Fatal(err)
	}
	if ch.Version != VersionTLS12 || !slices.Equal(ch.CipherSuites, spec.CipherSuites) || ch.ServerName != "kt.example" ||
		!slices.Equal(ch.SupportedVersions, spec.SupportedVersions) || !slices.Equal(ch.SupportedGroups, spec.SupportedGroups) ||
		!slices.Equal(ch.SignatureAlgorithms, spec.SignatureAlgorithms) || !slices.Equal(ch.ALPN, spec.ALPN) ||
		!ch.Has(ExtKeyShare) || len(ch.KeyShares) != 0 || !slices.Equal(ch.ECPointFormats, []uint8{0}) ||
		!ch.Has(ExtExtendedMasterSecret) || !ch.Has(ExtRenegotiationInfo) || !ch.Has(ExtSessionTicket) ||
		!ch.Has(ExtStatusRequest) || !slices.Equal(ch.PSKModes, []uint8{1}) || len(ch.SessionID) != 32 {
		t.Errorf("decoded %+v", ch)
	}
	ja3, sum := JA3(ch)
	if !strings.HasPrefix(ja3, "771,49195-4865,0-23-65281-10-11-35-16-5-13-43-45-51,31-26-23,0") || len(sum) != 32 {
		t.Errorf("JA3 %s %s", ja3, sum)
	}
}

func TestStreamFragments(t *testing.T) {
	spec := &HelloSpec{Version: VersionTLS12, CipherSuites: AllSuites(), SupportedGroups: []Group{0x17}}
	b := Records(VersionTLS10, append(spec.Marshal(), spec.Marshal()...))
	var s Stream
	var msgs []Message
	for i := range b {
		for _, e := range s.Feed(b[i : i+1]) {
			msgs = append(msgs, e.Messages...)
		}
	}
	if len(msgs) != 2 || s.Broken() {
		t.Fatalf("%d messages, broken %v", len(msgs), s.Broken())
	}
	var bad Stream
	bad.Feed([]byte("GET / HTTP/1.1\r\n"))
	if !bad.Broken() {
		t.Error("HTTP not detected as broken")
	}
}

// recorder captures what a net.Conn writes.
type recorder struct {
	net.Conn
	mu  sync.Mutex
	out []byte
}

func (r *recorder) Write(b []byte) (int, error) {
	r.mu.Lock()
	r.out = append(r.out, b...)
	r.mu.Unlock()
	return r.Conn.Write(b)
}

func selfSigned(t *testing.T) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "wire test"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// handshake runs a crypto/tls handshake and returns what the server wrote.
func handshake(t *testing.T, version uint16) []byte {
	t.Helper()
	c, s := net.Pipe()
	rec := &recorder{Conn: s}
	srv := tls.Server(rec, &tls.Config{
		Certificates: []tls.Certificate{selfSigned(t)}, ClientAuth: tls.RequestClientCert,
		MinVersion: version, MaxVersion: version, CurvePreferences: []tls.CurveID{tls.CurveP384},
	})
	cli := tls.Client(c, &tls.Config{InsecureSkipVerify: true, MinVersion: version, MaxVersion: version,
		CurvePreferences: []tls.CurveID{tls.CurveP384}})
	errc := make(chan error, 1)
	go func() { errc <- srv.Handshake() }()
	if err := cli.Handshake(); err != nil {
		t.Fatal(err)
	}
	if err := <-errc; err != nil {
		t.Fatal(err)
	}
	c.Close()
	s.Close()
	rec.mu.Lock()
	defer rec.mu.Unlock()
	return bytes.Clone(rec.out)
}

func TestTLS12Flight(t *testing.T) {
	events := SplitRecords(handshake(t, tls.VersionTLS12))
	var types []HandshakeType
	encrypted := 0
	for _, e := range events {
		for _, m := range e.Messages {
			types = append(types, m.Type)
			switch m.Type {
			case TypeServerHello:
				sh, err := ParseServerHello(m.Body)
				if err != nil || sh.Negotiated() != VersionTLS12 || !sh.Has(ExtExtendedMasterSecret) {
					t.Errorf("ServerHello %+v, %v", sh, err)
				}
			case TypeCertificate:
				certs, err := ParseCertificate(m.Body, false)
				if err != nil || len(certs) != 1 {
					t.Errorf("Certificate: %d, %v", len(certs), err)
				}
			case TypeServerKeyExchange:
				ske, err := ParseServerKeyExchange(m.Body, VersionTLS12)
				if err != nil || ske.Kind != "ECDHE" || ske.Group != 0x0018 || ske.SignatureScheme != 0x0403 {
					t.Errorf("ServerKeyExchange %+v, %v", ske, err)
				}
			case TypeCertificateRequest:
				cr, err := ParseCertificateRequest(m.Body, VersionTLS12)
				if err != nil || !slices.Contains(cr.CertificateTypes, 64) || len(cr.SignatureAlgorithms) == 0 {
					t.Errorf("CertificateRequest %+v, %v", cr, err)
				}
			}
			if d := Describe(m, VersionTLS12); len(d) == 0 && len(m.Body) > 0 {
				t.Errorf("no description of %v", m.Type)
			}
		}
		if e.Encrypted {
			encrypted++
		}
	}
	want := []HandshakeType{TypeServerHello, TypeCertificate, TypeServerKeyExchange, TypeCertificateRequest, TypeServerHelloDone}
	if !slices.Equal(types, want) || encrypted == 0 {
		t.Errorf("messages %v, %d encrypted records", types, encrypted)
	}
}

func TestTLS13Flight(t *testing.T) {
	events := SplitRecords(handshake(t, tls.VersionTLS13))
	if len(events) < 2 || len(events[0].Messages) != 1 || events[0].Messages[0].Type != TypeServerHello {
		t.Fatalf("first record %+v", events[0])
	}
	sh, err := ParseServerHello(events[0].Messages[0].Body)
	if err != nil || sh.Negotiated() != VersionTLS13 || sh.KeyShare != 0x0018 || sh.HelloRetryRequest {
		t.Errorf("ServerHello %+v, %v", sh, err)
	}
	for _, e := range events[1:] {
		if !e.Encrypted && !e.ChangeCipherSpec {
			t.Errorf("plaintext record after the ServerHello: %+v", e.Record)
		}
	}
}

func TestDescribeMalformed(t *testing.T) {
	for typ := range 30 {
		for _, body := range [][]byte{nil, {0}, {0, 1, 2}, bytes.Repeat([]byte{0xff}, 40)} {
			Describe(Message{Type: HandshakeType(typ), Body: body}, VersionTLS12)
		}
	}
}

func TestParseNames(t *testing.T) {
	if g, ok := ParseGroup("brainpoolP256r1"); !ok || g != 26 {
		t.Errorf("brainpoolP256r1: %v", g)
	}
	if g, ok := ParseGroup("P-384"); !ok || g != 24 {
		t.Errorf("P-384: %v", g)
	}
	if g, ok := ParseGroup("31"); !ok || g != 31 {
		t.Errorf("31: %v", g)
	}
	if s, ok := ParseCipherSuite("ECDHE_ECDSA_WITH_AES_128_GCM_SHA256"); !ok || s != 0xc02b {
		t.Errorf("suite: %v", s)
	}
	if s, ok := ParseCipherSuite("0xC030"); !ok || s != 0xc030 {
		t.Errorf("suite: %v", s)
	}
	if s, ok := ParseSignatureScheme("ecdsa_brainpoolP256r1tls13_sha256"); !ok || s != 0x081a {
		t.Errorf("scheme: %v", s)
	}
	if _, ok := ParseGroup("nonsense"); ok {
		t.Error("nonsense parsed")
	}
	if Version(0x0a0a).String() != "GREASE(0x0a0a)" || CipherSuite(0xc02b).Name() != "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256" {
		t.Error("names")
	}
}
