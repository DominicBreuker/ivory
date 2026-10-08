package main

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"fmt"
	"math/big"
	"net"
	"strings"
	"sync"
	"time"
)

// TLS extension and handshake message types used by the probes.
const (
	extSupportedGroups         = 10
	extSignatureAlgorithms     = 13
	extSignatureAlgorithmsCert = 50

	typeClientHello        = 1
	typeCertificateRequest = 13
)

// recorder captures everything read from and written to a net.Conn.
type recorder struct {
	net.Conn
	mu      sync.Mutex
	in, out []byte
}

func (r *recorder) Read(b []byte) (int, error) {
	n, err := r.Conn.Read(b)
	r.mu.Lock()
	r.in = append(r.in, b[:n]...)
	r.mu.Unlock()
	return n, err
}

func (r *recorder) Write(b []byte) (int, error) {
	r.mu.Lock()
	r.out = append(r.out, b...)
	r.mu.Unlock()
	return r.Conn.Write(b)
}

type handshakeMessage struct {
	typ  byte
	body []byte
}

// handshakeMessages returns the plaintext handshake messages in a byte stream
// of TLS records, stopping at the first non-handshake record.
func handshakeMessages(stream []byte) []handshakeMessage {
	var buf []byte
	for len(stream) >= 5 {
		typ, n := stream[0], int(binary.BigEndian.Uint16(stream[3:5]))
		if typ != 22 || len(stream) < 5+n {
			break
		}
		buf = append(buf, stream[5:5+n]...)
		stream = stream[5+n:]
	}
	var msgs []handshakeMessage
	for len(buf) >= 4 {
		n := int(buf[1])<<16 | int(buf[2])<<8 | int(buf[3])
		if len(buf) < 4+n {
			break
		}
		msgs = append(msgs, handshakeMessage{buf[0], buf[4 : 4+n]})
		buf = buf[4+n:]
	}
	return msgs
}

// findMessage returns the body of the first handshake message of type typ.
func findMessage(stream []byte, typ byte) []byte {
	for _, m := range handshakeMessages(stream) {
		if m.typ == typ {
			return m.body
		}
	}
	return nil
}

// cipherSuites returns the cipher_suites of a ClientHello body.
func cipherSuites(ch []byte) []uint16 {
	p := ch[2+32:]      // legacy_version, random
	p = p[1+int(p[0]):] // legacy_session_id
	return uint16s(p[2 : 2+int(binary.BigEndian.Uint16(p))])
}

// extension returns the body of extension want in a ClientHello body, or nil.
func extension(ch []byte, want uint16) []byte {
	p := ch[2+32:]
	p = p[1+int(p[0]):]
	p = p[2+int(binary.BigEndian.Uint16(p)):] // cipher_suites
	p = p[1+int(p[0]):]                       // compression_methods
	p = p[2:]                                 // extensions length
	for len(p) >= 4 {
		typ, n := binary.BigEndian.Uint16(p), int(binary.BigEndian.Uint16(p[2:]))
		if typ == want {
			return p[4 : 4+n]
		}
		p = p[4+n:]
	}
	return nil
}

// listExtension decodes an extension body that is a uint16 list with a
// two-byte length prefix (supported_groups, signature_algorithms).
func listExtension(ext []byte) []uint16 {
	if len(ext) < 2 {
		return nil
	}
	return uint16s(ext[2:])
}

// certificateTypes returns the certificate_types of a TLS 1.2
// CertificateRequest body.
func certificateTypes(cr []byte) []byte {
	if len(cr) < 1 || len(cr) < 1+int(cr[0]) {
		return nil
	}
	return cr[1 : 1+int(cr[0])]
}

func uint16s(b []byte) []uint16 {
	var out []uint16
	for i := 0; i+1 < len(b); i += 2 {
		out = append(out, binary.BigEndian.Uint16(b[i:]))
	}
	return out
}

func selfSigned() tls.Certificate {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}
	return selfSignedWith(key)
}

// selfSignedRSA is like selfSigned with a 2048-bit RSA key, for the
// ECDHE_RSA suites.
func selfSignedRSA() tls.Certificate {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}
	return selfSignedWith(key)
}

func selfSignedWith(key crypto.Signer) tls.Certificate {
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "localhost"},
		DNSNames:     []string{"localhost"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		panic(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// handshake runs one Go client against one Go server over loopback TCP and
// returns the bytes the client sent and received.
func handshake(client, server *tls.Config) (*recorder, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	defer ln.Close()
	errc := make(chan error, 1)
	go func() {
		s, err := ln.Accept()
		if err != nil {
			errc <- err
			return
		}
		srv := tls.Server(s, server)
		errc <- srv.Handshake()
		srv.Close()
	}()
	c, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		return nil, err
	}
	rec := &recorder{Conn: c}
	cli := tls.Client(rec, client)
	err = cli.Handshake()
	cli.Close()
	if serr := <-errc; err == nil {
		err = serr
	}
	return rec, err
}

var suiteNames = map[uint16]string{
	0xc02b: "ECDHE_ECDSA_AES_128_GCM_SHA256",
	0xc02c: "ECDHE_ECDSA_AES_256_GCM_SHA384",
	0xc02f: "ECDHE_RSA_AES_128_GCM_SHA256",
	0xc030: "ECDHE_RSA_AES_256_GCM_SHA384",
	0x1301: "TLS_AES_128_GCM_SHA256",
	0x1302: "TLS_AES_256_GCM_SHA384",
	0x1303: "TLS_CHACHA20_POLY1305_SHA256",
}

var groupNames = map[uint16]string{
	0x0017: "secp256r1",
	0x0018: "secp384r1",
	0x0019: "secp521r1",
	0x001a: "brainpoolP256r1",
	0x001b: "brainpoolP384r1",
	0x001c: "brainpoolP512r1",
	0x001d: "x25519",
	0x001f: "brainpoolP256r1tls13",
	0x0020: "brainpoolP384r1tls13",
	0x0021: "brainpoolP512r1tls13",
	0x11ec: "X25519MLKEM768",
	0x11eb: "SecP256r1MLKEM768",
	0x11ed: "SecP384r1MLKEM1024",
}

// schemeNames are the TLS SignatureScheme names (RFC 8446, RFC 8734,
// draft-ietf-tls-mldsa).
var schemeNames = map[uint16]string{
	0x0201: "rsa_pkcs1_sha1",
	0x0203: "ecdsa_sha1",
	0x0401: "rsa_pkcs1_sha256",
	0x0501: "rsa_pkcs1_sha384",
	0x0601: "rsa_pkcs1_sha512",
	0x0403: "ecdsa_secp256r1_sha256",
	0x0503: "ecdsa_secp384r1_sha384",
	0x0603: "ecdsa_secp521r1_sha512",
	0x0804: "rsa_pss_rsae_sha256",
	0x0805: "rsa_pss_rsae_sha384",
	0x0806: "rsa_pss_rsae_sha512",
	0x0807: "ed25519",
	0x0809: "rsa_pss_pss_sha256",
	0x080a: "rsa_pss_pss_sha384",
	0x080b: "rsa_pss_pss_sha512",
	0x081a: "ecdsa_brainpoolP256r1tls13_sha256",
	0x081b: "ecdsa_brainpoolP384r1tls13_sha384",
	0x081c: "ecdsa_brainpoolP512r1tls13_sha512",
	0x0904: "mldsa44",
	0x0905: "mldsa65",
	0x0906: "mldsa87",
}

// show formats a list of TLS code points with their names.
func show(names map[uint16]string, ids []uint16) string {
	if ids == nil {
		return "(absent)"
	}
	var s []string
	for _, id := range ids {
		if n, ok := names[id]; ok {
			s = append(s, fmt.Sprintf("%s(0x%04x)", n, id))
		} else {
			s = append(s, fmt.Sprintf("0x%04x", id))
		}
	}
	return strings.Join(s, ", ")
}
