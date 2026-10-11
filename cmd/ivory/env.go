//go:build ivory

package main

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/DominicBreuker/ivory/ocsp"
	"github.com/DominicBreuker/ivory/ti"
	"github.com/DominicBreuker/ivory/tsl"
)

// An environment is one of the TI's environments with the source of its
// trust space: the TSL and the TSL signer CA certificate (the trust
// anchor) that the TSL service publishes (gemSpec_TSL TIP1-A_4074).
type environment struct {
	name, label     string
	tslURL          string
	anchorURL       string
	anchorSHA256    string
	activeNeedsFlag bool
}

// The anchors' fingerprints are those that the TSL service publishes; a
// product must confirm them through an independent channel before it
// trusts them (gemSpec_PKI GS-A_4640).
var environments = []environment{
	{
		name:         "tu",
		label:        "test environment (TU)",
		tslURL:       "https://download-test.tsl.ti-dienste.de/ECC/ECC-RSA_TSL-test.xml",
		anchorURL:    "https://download-test.tsl.ti-dienste.de/ECC/C.GEM.TSL-CA28_TEST-ONLY.der",
		anchorSHA256: "43853a0e92bfd6e9e99f02c1d165a688aa94f0df74d8ea0ddf849ecd01be1d6a",
	},
	{
		name:         "ru",
		label:        "reference environment (RU)",
		tslURL:       "https://download-ref.tsl.ti-dienste.de/ECC/ECC-RSA_TSL-ref.xml",
		anchorURL:    "https://download-test.tsl.ti-dienste.de/ECC/C.GEM.TSL-CA28_TEST-ONLY.der",
		anchorSHA256: "43853a0e92bfd6e9e99f02c1d165a688aa94f0df74d8ea0ddf849ecd01be1d6a",
	},
	{
		name:            "pu",
		label:           "production environment (PU)",
		tslURL:          "https://download.tsl.ti-dienste.de/ECC/ECC-RSA_TSL.xml",
		anchorURL:       "https://download.tsl.ti-dienste.de/ECC/GEM.TSL-CA3.der",
		anchorSHA256:    "e2992dc292f6aa8d9e462a7723f54c162853b4056c277260b82ce58921408448",
		activeNeedsFlag: true,
	},
}

func lookupEnvironment(name string) (environment, bool) {
	for _, e := range environments {
		if e.name == strings.ToLower(name) {
			return e, true
		}
	}
	return environment{}, false
}

// trustFlags are the options that select the trust space for checking
// the peer's certificate.
type trustFlags struct {
	env, tslSource, anchorFile string
	caFiles                    listFlag
	noOCSP, refresh, allowPU   bool
	ocspTimeout                time.Duration
	// client makes the TSL and OCSP requests; nil means
	// http.DefaultClient.
	client *http.Client
}

func (f *trustFlags) register(fs *flag.FlagSet, active bool) {
	fs.StringVar(&f.env, "env", "", "TI environment whose trust space checks the peer certificate: tu, ru or pu (TSL downloaded and cached)")
	fs.StringVar(&f.tslSource, "tsl", "", "TSL file or URL instead of the environment's")
	fs.StringVar(&f.anchorFile, "trust-anchor", "", "TSL signer CA certificate (PEM or DER) instead of the environment's pinned one")
	fs.Var(&f.caFiles, "ca", "CA certificate file (PEM) that may issue the peer certificate; repeatable")
	fs.BoolVar(&f.noOCSP, "no-ocsp", false, "don't ask the OCSP responder of the TSL about the peer certificate")
	fs.BoolVar(&f.refresh, "refresh-tsl", false, "download the TSL even if the cached one is current")
	fs.DurationVar(&f.ocspTimeout, "ocsp-timeout", ocsp.DefaultTimeout, "OCSP request timeout")
	if active {
		fs.BoolVar(&f.allowPU, "allow-pu", false, "allow -env pu: connect to a product of the production environment (only with its operator's permission)")
	}
}

// guard refuses active connections in the production environment without
// -allow-pu.
func (f *trustFlags) guard() error {
	if e, ok := lookupEnvironment(f.env); ok && e.activeNeedsFlag && !f.allowPU {
		return errors.New("-env pu selects the production environment: products there are in operation for patients; " +
			"connect only with the operator's permission and confirm with -allow-pu")
	}
	return nil
}

// A trustSpace checks certificates against a TSL and extra CAs.
type trustSpace struct {
	env     string
	tsl     *tsl.TSL
	cas     []*x509.Certificate
	checker *ocsp.Checker
}

// load builds the trust space, or returns nil if no option asks for one.
// logf reports progress.
func (f *trustFlags) load(ctx context.Context, logf func(string, ...any)) (*trustSpace, error) {
	if f.env == "" && f.tslSource == "" && len(f.caFiles) == 0 {
		return nil, nil
	}
	ts := &trustSpace{}
	for _, file := range f.caFiles {
		certs, err := readCertificates(file)
		if err != nil {
			return nil, fmt.Errorf("-ca: %w", err)
		}
		ts.cas = append(ts.cas, certs...)
	}
	var env environment
	if f.env != "" {
		var ok bool
		if env, ok = lookupEnvironment(f.env); !ok {
			return nil, fmt.Errorf("-env: unknown environment %q (tu, ru or pu)", f.env)
		}
		ts.env = env.name
	}
	if f.env == "" && f.tslSource == "" {
		return ts, nil
	}
	anchor, err := f.trustAnchor(ctx, env, logf)
	if err != nil {
		return nil, err
	}
	data, source, err := f.tslData(ctx, env, logf)
	if err != nil {
		return nil, err
	}
	t, err := tsl.Parse(data)
	if err != nil {
		return nil, fmt.Errorf("TSL from %s: %w", source, err)
	}
	if _, err := t.Verify(tsl.VerifyOptions{TrustAnchors: []*x509.Certificate{anchor}}); err != nil {
		return nil, fmt.Errorf("TSL from %s: %w", source, err)
	}
	if t.Expired(time.Now(), 0) {
		logf("warning: the TSL's NextUpdate %v has passed", t.NextUpdate.UTC().Format(time.RFC3339))
	}
	logf("TSL sequence %d of %s, issued %v, signature valid (%d CA services)", t.SequenceNumber, source,
		t.IssueDate.UTC().Format(time.RFC3339), len(t.ServicesOfType(tsl.TypeCA)))
	ts.tsl = t
	if !f.noOCSP {
		ts.checker = &ocsp.Checker{Client: f.client, Timeout: f.ocspTimeout}
	}
	return ts, nil
}

func (f *trustFlags) trustAnchor(ctx context.Context, env environment, logf func(string, ...any)) (*x509.Certificate, error) {
	if f.anchorFile != "" {
		certs, err := readCertificates(f.anchorFile)
		if err != nil {
			return nil, fmt.Errorf("-trust-anchor: %w", err)
		}
		return certs[0], nil
	}
	if env.name == "" {
		return nil, errors.New("-tsl needs -env or -trust-anchor to check the TSL's signature")
	}
	der, err := cached(ctx, f.client, env.name, path.Base(env.anchorURL), env.anchorURL, f.refresh, logf)
	if err != nil {
		return nil, fmt.Errorf("trust anchor: %w", err)
	}
	if sum := sha256.Sum256(der); hex.EncodeToString(sum[:]) != env.anchorSHA256 {
		return nil, fmt.Errorf("trust anchor from %s has SHA-256 %x, want the pinned %s", env.anchorURL, sum, env.anchorSHA256)
	}
	return x509.ParseCertificate(der)
}

func (f *trustFlags) tslData(ctx context.Context, env environment, logf func(string, ...any)) ([]byte, string, error) {
	switch {
	case strings.HasPrefix(f.tslSource, "http://") || strings.HasPrefix(f.tslSource, "https://"):
		logf("downloading %s", f.tslSource)
		b, err := download(ctx, f.client, f.tslSource)
		return b, f.tslSource, err
	case f.tslSource != "":
		b, err := os.ReadFile(f.tslSource)
		return b, f.tslSource, err
	}
	name := path.Base(env.tslURL)
	if !f.refresh {
		if b, err := readCache(env.name, name); err == nil {
			if t, err := tsl.Parse(b); err == nil && !t.Expired(time.Now(), 0) {
				return b, env.tslURL + " (cached)", nil
			}
		}
	}
	b, err := cached(ctx, f.client, env.name, name, env.tslURL, true, logf)
	return b, env.tslURL, err
}

// cacheDir returns the directory for downloaded files of an environment,
// or "" if there is no cache directory.
func cacheDir(env string) string {
	dir, err := os.UserCacheDir()
	if err != nil {
		return ""
	}
	return filepath.Join(dir, "ivory", "tsl", env)
}

func readCache(env, name string) ([]byte, error) {
	dir := cacheDir(env)
	if dir == "" {
		return nil, errors.New("no cache directory")
	}
	return os.ReadFile(filepath.Join(dir, name))
}

// cached returns the file name of env from the cache, or downloads it from
// url (always if refresh is set) and stores it there.
func cached(ctx context.Context, client *http.Client, env, name, url string, refresh bool, logf func(string, ...any)) ([]byte, error) {
	if !refresh {
		if b, err := readCache(env, name); err == nil {
			return b, nil
		}
	}
	logf("downloading %s", url)
	b, err := download(ctx, client, url)
	if err != nil {
		return nil, err
	}
	if dir := cacheDir(env); dir != "" {
		if err := os.MkdirAll(dir, 0o755); err == nil {
			_ = os.WriteFile(filepath.Join(dir, name), b, 0o644)
		}
	}
	return b, nil
}

// download fetches url. It tries four times: the TSL service's hosts
// sometimes answer 404 for files they serve on the next request.
func download(ctx context.Context, client *http.Client, url string) ([]byte, error) {
	var err error
	for i := range 4 {
		if i > 0 {
			select {
			case <-time.After(time.Duration(i) * time.Second):
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		}
		var b []byte
		if b, err = get(ctx, client, url); err == nil {
			return b, nil
		}
	}
	return nil, err
}

func get(ctx context.Context, client *http.Client, url string) ([]byte, error) {
	if client == nil {
		client = http.DefaultClient
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GET %s: %s", url, resp.Status)
	}
	return io.ReadAll(io.LimitReader(resp.Body, 64<<20))
}

// readCertificates reads the certificates of a PEM file, or a single DER
// certificate.
func readCertificates(file string) ([]*x509.Certificate, error) {
	b, err := os.ReadFile(file)
	if err != nil {
		return nil, err
	}
	var certs []*x509.Certificate
	rest := b
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		c, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", file, err)
		}
		certs = append(certs, c)
	}
	if len(certs) == 0 {
		c, err := x509.ParseCertificate(b)
		if err != nil {
			return nil, fmt.Errorf("%s: no certificate", file)
		}
		certs = append(certs, c)
	}
	return certs, nil
}

// A TICheck is the result of checking a peer certificate the TI way:
// issued directly by a CA of the trust space (no path building), valid,
// the CA's status in the TSL, and the OCSP status (gemSpec_PKI
// TUC_PKI_018).
type TICheck struct {
	Environment   string `json:"environment,omitempty"`
	TSLSequence   int64  `json:"tsl_sequence,omitempty"`
	IssuerCA      string `json:"issuer_ca,omitempty"`
	IssuerService string `json:"issuer_service,omitempty"`
	IssuerStatus  string `json:"issuer_status,omitempty"`
	OCSP          string `json:"ocsp,omitempty"`
	OCSPResponder string `json:"ocsp_responder,omitempty"`
	Result        string `json:"result"`
	Error         string `json:"error,omitempty"`
}

func (ts *trustSpace) check(ctx context.Context, leaf *x509.Certificate) *TICheck {
	r := &TICheck{Environment: ts.env, Result: "ok"}
	fail := func(err error) *TICheck {
		r.Result, r.Error = "failed", err.Error()
		return r
	}
	v := &ti.Verifier{CAs: slices.Clone(ts.cas)}
	var service *tsl.Service
	var ca *x509.Certificate
	if ts.tsl != nil {
		r.TSLSequence = ts.tsl.SequenceNumber
		v.CAs = append(v.CAs, ts.tsl.CAs()...)
		v.Status = ts.tsl.Status(tsl.StatusOptions{})
		var err error
		if service, ca, err = ts.tsl.IssuerService(leaf); err == nil {
			r.IssuerCA = ca.Subject.String()
			r.IssuerService = service.Name
			r.IssuerStatus = path.Base(service.Status)
		}
	}
	if err := v.Verify(leaf, ""); err != nil {
		return fail(err)
	}
	if service == nil {
		for _, c := range ts.cas {
			if string(c.RawSubject) == string(leaf.RawIssuer) {
				r.IssuerCA = c.Subject.String()
			}
		}
		r.OCSP = "not asked (no TSL)"
		return r
	}
	if ts.checker == nil {
		r.OCSP = "not asked (-no-ocsp)"
		return r
	}
	r.OCSPResponder = service.OCSPLocation()
	_, sr, err := ts.checker.Check(ctx, leaf, ca, r.OCSPResponder, ts.tsl.OCSPResponders())
	if err != nil {
		r.OCSP = "error"
		return fail(err)
	}
	r.OCSP = sr.Status.String()
	if sr.Status == ocsp.Revoked {
		r.OCSP += " at " + sr.RevokedAt.UTC().Format(time.RFC3339)
	}
	if sr.Status != ocsp.Good {
		return fail(fmt.Errorf("OCSP status %s", r.OCSP))
	}
	return r
}

// listFlag is a repeatable string flag.
type listFlag []string

func (l *listFlag) String() string { return strings.Join(*l, ",") }

func (l *listFlag) Set(s string) error {
	*l = append(*l, s)
	return nil
}
