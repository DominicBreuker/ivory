package ocsp

import (
	"bytes"
	"context"
	"crypto"
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"
)

// DefaultTimeout is the default time limit for a request (TUC_PKI_006,
// parameter "Timeout-Parameter (Default: 10s)").
const DefaultTimeout = 10 * time.Second

// maxResponseSize limits the size of a response read from a responder.
const maxResponseSize = 1 << 20

// A Checker asks OCSP responders about certificates and verifies their
// answers: TUC_PKI_006 (gemSpec_PKI V2.28.0, GS-A_4657-03) without the
// lookup of the responder's address and certificates, which the caller
// takes from the TSL (package tsl does that).
//
// A Checker is safe for concurrent use. The zero value works: no cache,
// a 10 second timeout, SHA-1 CertIDs, the tolerances of GS-A_5215 and the
// certHash check on.
type Checker struct {
	// Client sends the requests. If nil, http.DefaultClient is used.
	Client *http.Client

	// Timeout limits each request. If zero, DefaultTimeout is used.
	Timeout time.Duration

	// GracePeriod is how long a good response is reused, measured from
	// its producedAt (TUC_PKI_006 step 1, "OCSP-Graceperiod"; the
	// specification's default is 10 minutes). Zero turns the cache off.
	GracePeriod time.Duration

	// Hash is the hash of the CertID in requests. If zero, SHA-1 is used.
	Hash crypto.Hash

	// ProducedAtPast, ProducedAtFuture, UpdateTolerance and SkipCertHash
	// are passed to Response.Verify.
	ProducedAtPast, ProducedAtFuture, UpdateTolerance time.Duration
	SkipCertHash                                      bool

	// Time returns the current time. If nil, time.Now is used.
	Time func() time.Time

	mu    sync.Mutex
	cache map[[64]byte]cached
}

type cached struct {
	resp *Response
	sr   *SingleResponse
}

func (c *Checker) now() time.Time {
	if c.Time != nil {
		return c.Time()
	}
	return time.Now()
}

func cacheKey(cert, issuer *x509.Certificate) [64]byte {
	var k [64]byte
	a := sha256.Sum256(cert.Raw)
	b := sha256.Sum256(issuer.Raw)
	copy(k[:32], a[:])
	copy(k[32:], b[:])
	return k
}

// Check returns the verified status of cert, issued by issuer, from the
// responder at url, whose response must be signed by one of responders.
// It returns the response and the single response about cert. If the
// certificate isn't good, or no valid answer arrives, the error wraps one
// of the Err values of this package; errors.Is(err, ErrNotAvailable)
// tells the caller that the responder couldn't be reached, for example to
// apply TOLERATE_OCSP_FAILURE.
func (c *Checker) Check(ctx context.Context, cert, issuer *x509.Certificate, url string, responders []*x509.Certificate) (*Response, *SingleResponse, error) {
	if cert == nil || issuer == nil {
		return nil, nil, errors.New("ocsp: Check needs the certificate and its issuer")
	}
	key := cacheKey(cert, issuer)
	if c.GracePeriod > 0 {
		c.mu.Lock()
		e, ok := c.cache[key]
		c.mu.Unlock()
		if ok && !c.now().After(e.resp.ProducedAt.Add(c.GracePeriod)) {
			return e.resp, e.sr, nil
		}
	}
	if url == "" {
		return nil, nil, fmt.Errorf("ocsp: no responder address for %q: %w", cert.Subject, ErrCheckRevocation)
	}
	req, err := CreateRequest(cert, issuer, &RequestOptions{Hash: c.Hash})
	if err != nil {
		return nil, nil, fmt.Errorf("%w: %w", ErrCheckRevocation, err)
	}
	der, err := c.post(ctx, url, req)
	if err != nil {
		return nil, nil, err
	}
	received := c.now()
	resp, err := ParseResponse(der)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: %w", ErrCheckRevocation, err)
	}
	sr, err := resp.Verify(cert, VerifyOptions{
		Issuer:           issuer,
		Responders:       responders,
		Time:             received,
		ProducedAtPast:   c.ProducedAtPast,
		ProducedAtFuture: c.ProducedAtFuture,
		UpdateTolerance:  c.UpdateTolerance,
		SkipCertHash:     c.SkipCertHash,
	})
	if err != nil {
		return resp, sr, err
	}
	if c.GracePeriod > 0 {
		c.mu.Lock()
		if c.cache == nil {
			c.cache = make(map[[64]byte]cached)
		}
		c.cache[key] = cached{resp, sr}
		c.mu.Unlock()
	}
	return resp, sr, nil
}

// Flush empties the cache, for example after the trust space changed.
func (c *Checker) Flush() {
	c.mu.Lock()
	c.cache = nil
	c.mu.Unlock()
}

func (c *Checker) post(ctx context.Context, url string, body []byte) ([]byte, error) {
	timeout := c.Timeout
	if timeout == 0 {
		timeout = DefaultTimeout
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	hr, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("ocsp: %w: %w", ErrNotAvailable, err)
	}
	hr.Header.Set("Content-Type", "application/ocsp-request")
	hr.Header.Set("Accept", "application/ocsp-response")
	client := c.Client
	if client == nil {
		client = http.DefaultClient
	}
	res, err := client.Do(hr)
	if err != nil {
		return nil, fmt.Errorf("ocsp: %w: %w", ErrNotAvailable, err)
	}
	defer res.Body.Close()
	data, err := io.ReadAll(io.LimitReader(res.Body, maxResponseSize+1))
	if err != nil {
		return nil, fmt.Errorf("ocsp: %w: %w", ErrNotAvailable, err)
	}
	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("ocsp: responder %s answered HTTP %d: %w", url, res.StatusCode, ErrNotAvailable)
	}
	if len(data) > maxResponseSize {
		return nil, fmt.Errorf("ocsp: response from %s too large: %w", url, ErrCheckRevocation)
	}
	return data, nil
}
