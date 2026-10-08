// Command probe records what crypto/tls puts on the wire for the TLS details
// that gemSpec_Krypt and gemSpec_KT regulate (see README.md). It
// needs no Brainpool code and no network access; K5 and K7 listen on a local
// address for an OpenSSL peer.
//
// Probes:
//
//	K1  TLS 1.2 ClientHello cipher_suites order (A_17124-03 item 3, A_17094-02)
//	K2  TLS 1.3 ClientHello cipher_suites with Config.CipherSuites restricted
//	    (A_17322, A_18467 via BSI TR-02102-2)
//	K3  TLS 1.2 CertificateRequest certificate_types (A_22454)
//	K4  supported_groups with CurvePreferences = P-256, P-384 (GS-A_4384-03)
//	K5  a client renegotiates against a Go server (GS-A_5524); run with -k5
//	K6  signature_algorithms and signature_algorithms_cert in the TLS 1.2 and
//	    TLS 1.3 ClientHello (A_18467 via BSI TR-02102-2)
//	K7  TLS 1.3 server with AES-only Config.CipherSuites; run with -k7
//
// Usage:
//
//	probe                 print K1-K4 and K6
//	probe -k5 <addr>      accept one TLS 1.2 connection for K5
//	probe -k7 <addr>      accept one TLS 1.3 connection for K7
//
// Build it with the toolchain and overlay under test. See README.md for the
// OpenSSL command lines.
package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"net"
	"os"
	"runtime"
)

// tiSuites are the TI's TLS 1.2 cipher suites, listed in the order gematik
// wants: ECDSA first (A_17124-03).
var tiSuites = []uint16{
	tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
	tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
	tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
	tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
}

// tls12Result is what a TLS 1.2 Go client sends and receives (K1, K3, K4,
// K6). certTypes is from a server with an ECDSA certificate (an ECDHE_ECDSA
// suite), certTypesRSA from one with an RSA certificate (ECDHE_RSA).
type tls12Result struct {
	suites, groups, sigAlgs, sigAlgsCert []uint16
	certTypes, certTypesRSA              []byte
}

// probeTLS12 runs TLS 1.2 handshakes between a Go client with the TI's
// suites and curves and Go servers, with an ECDSA and with an RSA
// certificate, that request a client certificate.
func probeTLS12() (*tls12Result, error) {
	client := &tls.Config{
		InsecureSkipVerify: true,
		MaxVersion:         tls.VersionTLS12,
		CipherSuites:       tiSuites,
		CurvePreferences:   []tls.CurveID{tls.CurveP256, tls.CurveP384},
	}
	rec, err := handshake(client, &tls.Config{
		Certificates: []tls.Certificate{selfSigned()},
		ClientAuth:   tls.RequestClientCert,
	})
	if err != nil {
		return nil, fmt.Errorf("TLS 1.2 handshake: %v", err)
	}
	recRSA, err := handshake(client, &tls.Config{
		Certificates: []tls.Certificate{selfSignedRSA()},
		ClientAuth:   tls.RequestClientCert,
	})
	if err != nil {
		return nil, fmt.Errorf("TLS 1.2 handshake (RSA): %v", err)
	}
	ch := findMessage(rec.out, typeClientHello)
	if ch == nil {
		return nil, fmt.Errorf("no ClientHello recorded")
	}
	return &tls12Result{
		suites:       cipherSuites(ch),
		groups:       listExtension(extension(ch, extSupportedGroups)),
		sigAlgs:      listExtension(extension(ch, extSignatureAlgorithms)),
		sigAlgsCert:  listExtension(extension(ch, extSignatureAlgorithmsCert)),
		certTypes:    certificateTypes(findMessage(rec.in, typeCertificateRequest)),
		certTypesRSA: certificateTypes(findMessage(recRSA.in, typeCertificateRequest)),
	}, nil
}

// tls13Result is what a TLS 1.3 Go client sends (K2, K6).
type tls13Result struct {
	suites, sigAlgs, sigAlgsCert []uint16
}

// probeTLS13 runs a TLS 1.3 handshake with a Go client whose
// Config.CipherSuites lists only AES-GCM.
func probeTLS13() (*tls13Result, error) {
	rec, err := handshake(&tls.Config{
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS13,
		CipherSuites:       []uint16{tls.TLS_AES_128_GCM_SHA256, tls.TLS_AES_256_GCM_SHA384},
		CurvePreferences:   []tls.CurveID{tls.CurveP256, tls.CurveP384},
	}, &tls.Config{Certificates: []tls.Certificate{selfSigned()}})
	if err != nil {
		return nil, fmt.Errorf("TLS 1.3 handshake: %v", err)
	}
	ch := findMessage(rec.out, typeClientHello)
	if ch == nil {
		return nil, fmt.Errorf("no ClientHello recorded")
	}
	return &tls13Result{
		suites:      cipherSuites(ch),
		sigAlgs:     listExtension(extension(ch, extSignatureAlgorithms)),
		sigAlgsCert: listExtension(extension(ch, extSignatureAlgorithmsCert)),
	}, nil
}

// renegServer accepts one TLS 1.2 connection on ln and returns the error
// that ends it, usually after the client attempts a renegotiation (K5,
// GS-A_5524). Data read before that is passed to logf.
func renegServer(ln net.Listener, logf func(format string, args ...any)) error {
	c, err := ln.Accept()
	if err != nil {
		return err
	}
	defer c.Close()
	tc := tls.Server(c, &tls.Config{
		Certificates: []tls.Certificate{selfSigned()},
		MaxVersion:   tls.VersionTLS12,
	})
	buf := make([]byte, 1024)
	for {
		n, err := tc.Read(buf)
		if err != nil {
			return err
		}
		logf("K5 server read %q", buf[:n])
	}
}

// tls13Server accepts one TLS 1.3 connection on ln with Config.CipherSuites
// restricted to AES-GCM and returns the cipher suite it negotiated (K7).
// Config.CipherSuites does not apply to TLS 1.3, so a client that offers
// only ChaCha20-Poly1305 still connects.
func tls13Server(ln net.Listener) (uint16, error) {
	c, err := ln.Accept()
	if err != nil {
		return 0, err
	}
	defer c.Close()
	tc := tls.Server(c, &tls.Config{
		Certificates: []tls.Certificate{selfSigned()},
		MinVersion:   tls.VersionTLS13,
		CipherSuites: []uint16{tls.TLS_AES_128_GCM_SHA256, tls.TLS_AES_256_GCM_SHA384},
	})
	if err := tc.Handshake(); err != nil {
		return 0, err
	}
	return tc.ConnectionState().CipherSuite, nil
}

func main() {
	k5 := flag.String("k5", "", "accept one TLS 1.2 connection on `addr` and report a renegotiation attempt (K5)")
	k7 := flag.String("k7", "", "accept one TLS 1.3 connection on `addr` and report the cipher suite (K7)")
	flag.Parse()
	logf := func(format string, args ...any) { fmt.Printf(format+"\n", args...) }

	switch {
	case *k5 != "":
		ln, err := net.Listen("tcp", *k5)
		if err != nil {
			fatal(err)
		}
		fmt.Println("K5 listening on", ln.Addr())
		err = renegServer(ln, logf)
		fmt.Println("K5 server Read error after client renegotiation attempt:", err)
	case *k7 != "":
		ln, err := net.Listen("tcp", *k7)
		if err != nil {
			fatal(err)
		}
		fmt.Println("K7 listening on", ln.Addr())
		suite, err := tls13Server(ln)
		if err != nil {
			fmt.Println("K7 handshake error:", err)
			return
		}
		fmt.Println("K7 negotiated:", tls.CipherSuiteName(suite))
	default:
		fmt.Println("Go", runtime.Version())
		r12, err := probeTLS12()
		if err != nil {
			fatal(err)
		}
		fmt.Println("K1 TLS 1.2 ClientHello cipher_suites (Config.CipherSuites lists ECDSA first):")
		fmt.Println("   ", show(suiteNames, r12.suites))
		fmt.Println("K6 TLS 1.2 ClientHello signature_algorithms:")
		fmt.Println("   ", show(schemeNames, r12.sigAlgs))
		fmt.Println("K6 TLS 1.2 ClientHello signature_algorithms_cert:")
		fmt.Println("   ", show(schemeNames, r12.sigAlgsCert))
		fmt.Println("K4 supported_groups with CurvePreferences=[P-256, P-384]:")
		fmt.Println("   ", show(groupNames, r12.groups))
		fmt.Printf("K3 TLS 1.2 CertificateRequest certificate_types (1=rsa_sign, 64=ecdsa_sign): ECDHE_ECDSA % x, ECDHE_RSA % x\n", r12.certTypes, r12.certTypesRSA)

		r13, err := probeTLS13()
		if err != nil {
			fatal(err)
		}
		fmt.Println("K2 TLS 1.3 ClientHello cipher_suites (Config.CipherSuites=[AES_128_GCM, AES_256_GCM]):")
		fmt.Println("   ", show(suiteNames, r13.suites))
		fmt.Println("K6 TLS 1.3 ClientHello signature_algorithms:")
		fmt.Println("   ", show(schemeNames, r13.sigAlgs))
		fmt.Println("K6 TLS 1.3 ClientHello signature_algorithms_cert:")
		fmt.Println("   ", show(schemeNames, r13.sigAlgsCert))
	}
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "probe:", err)
	os.Exit(1)
}
