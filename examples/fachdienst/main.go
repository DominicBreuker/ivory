//go:build ivory

// Command fachdienst is an example TLS server of a TI service (a
// Fachdienst) that checks client certificates the way gemSpec_PKI
// requires: against the trust space of the TSL, which it keeps up to date
// (TUC_PKI_001), with the certificate's OCSP status (TUC_PKI_006 within
// TUC_PKI_018). TSL signatures, OCSP responses and client certificates
// may all use Brainpool keys.
//
// It imports the first TSL from a file or URL, verified against the TSL
// signer CA certificate given as trust anchor (offline, without OCSP),
// then checks the TSL's download points every -tsl-interval. It accepts
// a client whose certificate has one of the certificate types -policy,
// the key usage digitalSignature and the extended key usage clientAuth,
// and logs the result of every handshake.
//
// Usage, for example as the system under test of gematik's PKI test
// suite, product type KimFachdienst (certificate type C.CM.TLS-CS):
//
//	fachdienst -addr 127.0.0.1:8443 -cert server.pem -key server.key \
//		-tsl 'http://127.0.0.1:8084/tsl/tsl.xml?activeTslSeqNr=0' \
//		-trust-anchor GEM.TSL-CA51-TEST-ONLY.pem \
//		-policy 1.2.276.0.76.4.175 -tsl-interval 2s -ocsp-grace 30s
package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"log/slog"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/DominicBreuker/ivory/ocsp"
	"github.com/DominicBreuker/ivory/ti"
	"github.com/DominicBreuker/ivory/tlsutil"
	"github.com/DominicBreuker/ivory/tsl"
)

type options struct {
	addr, certFile, keyFile, tslSource, anchorFile, policies string
	tslInterval, tslGrace, ocspGrace, ocspTimeout            time.Duration
	producedAtPast, producedAtFuture                         time.Duration
	offline, tolerateOCSPFailure, skipCertHash               bool
}

func main() {
	var o options
	flag.StringVar(&o.addr, "addr", "127.0.0.1:8443", "listen `address`")
	flag.StringVar(&o.certFile, "cert", "", "server certificate (PEM)")
	flag.StringVar(&o.keyFile, "key", "", "server key (PEM, PKCS #8 or SEC 1; Brainpool, ECDSA or RSA)")
	flag.StringVar(&o.tslSource, "tsl", "", "initial TSL: a file or an http(s) URL")
	flag.StringVar(&o.anchorFile, "trust-anchor", "", "TSL signer CA certificate, the TI trust anchor (PEM or DER)")
	flag.StringVar(&o.policies, "policy", "", "comma-separated certificate type `OIDs` a client certificate may have")
	flag.DurationVar(&o.tslInterval, "tsl-interval", 24*time.Hour, "how often to check for a new TSL")
	flag.DurationVar(&o.tslGrace, "tsl-grace", 0, "TSL grace period after NextUpdate")
	flag.DurationVar(&o.ocspGrace, "ocsp-grace", 10*time.Minute, "how long to reuse a good OCSP response")
	flag.DurationVar(&o.ocspTimeout, "ocsp-timeout", ocsp.DefaultTimeout, "OCSP request timeout")
	flag.DurationVar(&o.producedAtPast, "ocsp-produced-at-past", ocsp.DefaultTolerance, "tolerance for producedAt in the past")
	flag.DurationVar(&o.producedAtFuture, "ocsp-produced-at-future", ocsp.DefaultTolerance, "tolerance for producedAt in the future")
	flag.BoolVar(&o.offline, "offline", false, "don't ask OCSP responders")
	flag.BoolVar(&o.tolerateOCSPFailure, "tolerate-ocsp-failure", false, "accept certificates when the OCSP responder can't be reached")
	flag.BoolVar(&o.skipCertHash, "skip-certhash", false, "don't require the certHash extension (eGK certificates)")
	flag.Parse()

	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	s, err := newServer(o, logger)
	if err != nil {
		log.Fatal(err)
	}
	ctx := context.Background()
	if err := s.init(ctx, o.tslSource, o.anchorFile); err != nil {
		log.Fatal(err)
	}
	go s.updateLoop(ctx, o.tslInterval)
	ln, err := net.Listen("tcp", o.addr)
	if err != nil {
		log.Fatal(err)
	}
	logger.Info("listening", "addr", ln.Addr().String())
	log.Fatal(s.serve(ln))
}

type server struct {
	updater  *tsl.Updater
	checker  *ocsp.Checker
	config   *tls.Config
	policies []x509.OID
	opts     options
	log      *slog.Logger
}

func newServer(o options, logger *slog.Logger) (*server, error) {
	if o.certFile == "" || o.keyFile == "" || o.tslSource == "" || o.anchorFile == "" {
		return nil, errors.New("need -cert, -key, -tsl and -trust-anchor")
	}
	cert, err := tlsutil.LoadX509KeyPair(o.certFile, o.keyFile)
	if err != nil {
		return nil, fmt.Errorf("server identity: %w", err)
	}
	s := &server{opts: o, log: logger}
	for _, p := range strings.Split(o.policies, ",") {
		if p = strings.TrimSpace(p); p == "" {
			continue
		}
		oid, err := x509.ParseOID(p)
		if err != nil {
			return nil, fmt.Errorf("-policy: %w", err)
		}
		s.policies = append(s.policies, oid)
	}
	s.checker = &ocsp.Checker{
		Timeout:          o.ocspTimeout,
		GracePeriod:      o.ocspGrace,
		ProducedAtPast:   o.producedAtPast,
		ProducedAtFuture: o.producedAtFuture,
		SkipCertHash:     o.skipCertHash,
	}
	s.updater = &tsl.Updater{Grace: o.tslGrace, Logger: logger}
	if !o.offline {
		// The TSL signer's status is always checked with certHash
		// (TUC_PKI_001 step 4), and asked afresh for every new TSL: no
		// grace period.
		s.updater.OCSP = &ocsp.Checker{Timeout: o.ocspTimeout,
			ProducedAtPast: o.producedAtPast, ProducedAtFuture: o.producedAtFuture}
	}
	// ServerConfig requires a client certificate; VerifyConnection is
	// replaced so that every handshake uses the current trust space.
	s.config = ti.ServerConfig([]tls.Certificate{cert}, &ti.Verifier{})
	s.config.VerifyConnection = s.verify
	return s, nil
}

// init imports the first TSL.
func (s *server) init(ctx context.Context, source, anchorFile string) error {
	der, err := os.ReadFile(anchorFile)
	if err != nil {
		return err
	}
	if block, _ := pem.Decode(der); block != nil {
		der = block.Bytes
	}
	anchor, err := x509.ParseCertificate(der)
	if err != nil {
		return fmt.Errorf("trust anchor: %w", err)
	}
	for {
		data, err := readSource(ctx, source)
		if err == nil {
			if err = s.updater.Init(data, anchor); err == nil {
				return nil
			}
		}
		s.log.Warn("initial TSL not imported, retrying", "err", err)
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(s.opts.tslInterval):
		}
	}
}

func readSource(ctx context.Context, source string) ([]byte, error) {
	if !strings.HasPrefix(source, "http://") && !strings.HasPrefix(source, "https://") {
		return os.ReadFile(source)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, source, nil)
	if err != nil {
		return nil, err
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s: HTTP %d", source, res.StatusCode)
	}
	return io.ReadAll(io.LimitReader(res.Body, 32<<20))
}

func (s *server) updateLoop(ctx context.Context, interval time.Duration) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		changed, err := s.updater.Update(ctx)
		switch {
		case err != nil:
			s.log.Warn("TSL update failed", "err", err)
		case changed:
			s.log.Info("trust space updated", "seq", s.updater.Current().SequenceNumber)
		}
	}
}

// verify checks the client certificate with the current trust space:
// TUC_PKI_018 with ti.Verifier and the TSL's status check.
func (s *server) verify(cs tls.ConnectionState) error {
	if len(cs.PeerCertificates) == 0 {
		return errors.New("no client certificate")
	}
	cur := s.updater.Current()
	if cur == nil {
		return errors.New("no valid TSL in the system")
	}
	opts := tsl.StatusOptions{
		Policies:            s.policies,
		TolerateOCSPFailure: s.opts.tolerateOCSPFailure,
		OnWarning:           func(err error) { s.log.Warn("OCSP_CHECK_REVOCATION_FAILED", "err", err) },
	}
	if !s.opts.offline {
		opts.OCSP = s.checker
	}
	v := &ti.Verifier{
		CAs:          cur.CAs(),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		Policies:     s.policies,
		Status:       cur.Status(opts),
	}
	return v.Verify(cs.PeerCertificates[0], "")
}

func (s *server) serve(ln net.Listener) error {
	for {
		c, err := ln.Accept()
		if err != nil {
			return err
		}
		go s.handle(c)
	}
}

func (s *server) handle(c net.Conn) {
	defer c.Close()
	c.SetDeadline(time.Now().Add(30 * time.Second))
	tc := tls.Server(c, s.config)
	if err := tc.Handshake(); err != nil {
		s.log.Info("handshake failed", "remote", c.RemoteAddr().String(), "err", err)
		return
	}
	cs := tc.ConnectionState()
	s.log.Info("handshake succeeded", "remote", c.RemoteAddr().String(),
		"client", cs.PeerCertificates[0].Subject.String(), "group", cs.CurveID, "suite", tls.CipherSuiteName(cs.CipherSuite))
	fmt.Fprintf(tc, "hello %s\n", cs.PeerCertificates[0].Subject.CommonName)
}
