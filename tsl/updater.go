package tsl

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/DominicBreuker/ivory/ocsp"
)

// Errors of the Updater, named after the error codes of gemSpec_PKI
// V2.28.0.
var (
	// ErrDownload: no download address delivered the TSL
	// (TSL_DOWNLOAD_ERROR, TUC_PKI_016 step 4a).
	ErrDownload = errors.New("TSL_DOWNLOAD_ERROR")
	// ErrDownloadAddress: the TSL has no download address
	// (TSL_DOWNLOAD_ADDRESS_ERROR, TUC_PKI_017 step 2a).
	ErrDownloadAddress = errors.New("TSL_DOWNLOAD_ADDRESS_ERROR")
	// ErrID: the new TSL is not newer than the TSL in the system
	// (TSL_ID_INCORRECT, TUC_PKI_019 step 6b).
	ErrID = errors.New("TSL_ID_INCORRECT")
	// ErrNoTrustSpace: there is no valid TSL in the system, for example
	// because its grace period ended (VALIDITY_WARNING_2, GS-A_5336); a
	// new TSL must be imported with Init.
	ErrNoTrustSpace = errors.New("VALIDITY_WARNING_2")
)

// maxTSLSize limits downloads; the production TSL(ECC-RSA) has about
// 1 MB.
const maxTSLSize = 32 << 20

var defaultClient = &http.Client{Timeout: time.Minute}

// downloadAttempts per address: the first try and three repetitions
// (TUC_PKI_016 step 3a).
const downloadAttempts = 4

// An Updater keeps the TI trust space up to date from the TSL
// (gemSpec_PKI V2.28.0, TUC_PKI_001 "Periodische Aktualisierung
// TI-Vertrauensraum" with TUC_PKI_013, TUC_PKI_016, TUC_PKI_017 and
// TUC_PKI_019). Call Init once with a TSL and the trust anchor, then
// Update periodically (daily by default per TUC_PKI_001; product
// specifications may say otherwise). Current returns the TSL to check
// certificates with.
//
// An Updater is safe for concurrent use.
type Updater struct {
	// Client downloads the TSL and its hash file. If nil, a client with
	// a one-minute timeout is used. Go's HTTP client asks for gzip
	// compression and decompresses (TIP1-A_5120).
	Client *http.Client

	// OCSP checks the TSL signer certificate before a new TSL is
	// accepted (TUC_PKI_001 step 4), with the responders and the address
	// of the TSL already in the system. If nil, the check is skipped
	// (offline mode, step 3a). Use a Checker without GracePeriod, so
	// that every new TSL gets a fresh answer (gematik's PKI test suite
	// expects one), and not the Checker for end-entity certificates.
	OCSP *ocsp.Checker

	// Grace is the TSL grace period: how long after its NextUpdate a TSL
	// may still be used (TUC_PKI_019 step 7a, GS-A_5336).
	Grace time.Duration

	// Time returns the current time. If nil, time.Now is used.
	Time func() time.Time

	// Logger receives what happened in each step. If nil, nothing is
	// logged.
	Logger *slog.Logger

	mu     sync.Mutex
	cur    *TSL
	hash   []byte
	anchor *x509.Certificate
	// future is an announced trust anchor, futureStart its
	// StatusStartingTime, futureService the TSLServiceCertChange entry
	// whose address the first signer check after the change uses
	// (TUC_PKI_001, note).
	future        *x509.Certificate
	futureStart   time.Time
	futureService *Service
}

func (u *Updater) now() time.Time {
	if u.Time != nil {
		return u.Time()
	}
	return time.Now()
}

func (u *Updater) log(msg string, args ...any) {
	if u.Logger != nil {
		u.Logger.Info(msg, args...)
	}
}

// Init imports a TSL into an Updater without a trust space (initial
// import, GS-A_4640): it parses data, verifies it against anchor, the
// TSL signer CA certificate the system stores as trust anchor, and makes
// it the current TSL. The signer's status is not checked (gemSpec_PKI
// V2.28.0, Section 8.1.2: initial import is offline).
func (u *Updater) Init(data []byte, anchor *x509.Certificate) error {
	t, err := Parse(data)
	if err != nil {
		return err
	}
	if _, err := t.Verify(VerifyOptions{TrustAnchors: []*x509.Certificate{anchor}, Time: u.now()}); err != nil {
		return err
	}
	u.mu.Lock()
	defer u.mu.Unlock()
	u.cur, u.hash, u.anchor = t, sum(data), anchor
	u.future, u.futureService = nil, nil
	u.announce(t)
	u.log("tsl: initial TSL imported", "seq", t.SequenceNumber, "id", t.ID)
	return nil
}

func sum(data []byte) []byte {
	h := (&TSL{Raw: data}).Hash()
	return h[:]
}

// Current returns the TSL of the trust space, or nil if there is none or
// it is past its NextUpdate and grace period (GS-A_5336).
func (u *Updater) Current() *TSL {
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.cur == nil || u.cur.Expired(u.now(), u.Grace) {
		return nil
	}
	return u.cur
}

// TrustAnchor returns the active trust anchor.
func (u *Updater) TrustAnchor() *x509.Certificate {
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.anchor
}

// Update runs one round of TUC_PKI_001: it compares the hash file at the
// download addresses with the TSL in the system, downloads a new TSL if
// they differ, and imports it with Import. It reports whether the trust
// space changed.
func (u *Updater) Update(ctx context.Context) (bool, error) {
	u.mu.Lock()
	cur, hash := u.cur, u.hash
	u.mu.Unlock()
	if cur == nil {
		return false, ErrNoTrustSpace
	}
	if cur.Expired(u.now(), u.Grace) {
		return false, fmt.Errorf("tsl: TSL %d expired at %v: %w", cur.SequenceNumber, cur.NextUpdate, ErrNoTrustSpace)
	}
	locs := append(append([]string(nil), cur.PrimaryLocations...), cur.BackupLocations...)
	if len(locs) == 0 {
		return false, fmt.Errorf("tsl: TSL %d: %w", cur.SequenceNumber, ErrDownloadAddress)
	}
	for _, loc := range locs {
		h, err := u.get(ctx, hashLocation(loc), 1024)
		if err != nil {
			u.log("tsl: hash download failed", "url", hashLocation(loc), "err", err)
			continue
		}
		if got, err := hex.DecodeString(strings.TrimSpace(string(h))); err == nil && bytes.Equal(got, hash) {
			u.log("tsl: hash unchanged", "seq", cur.SequenceNumber)
			return false, nil
		}
		break
	}
	data, err := u.download(ctx, cur)
	if err != nil {
		return false, err
	}
	return u.Import(ctx, data)
}

// hashLocation returns the address of the hash file of the TSL at loc:
// ".sha2" instead of ".xml" (TUC_PKI_019 step 1b).
func hashLocation(loc string) string {
	if i := strings.LastIndex(loc, ".xml"); i >= 0 {
		return loc[:i] + ".sha2" + loc[i+len(".xml"):]
	}
	return loc
}

// download fetches the TSL from the primary addresses, then from the
// backup addresses, each up to four times (TUC_PKI_016).
func (u *Updater) download(ctx context.Context, cur *TSL) ([]byte, error) {
	for _, locs := range [][]string{cur.PrimaryLocations, cur.BackupLocations} {
		for _, loc := range locs {
			for i := 0; i < downloadAttempts; i++ {
				data, err := u.get(ctx, loc, maxTSLSize)
				if err == nil {
					u.log("tsl: downloaded", "url", loc, "bytes", len(data))
					return data, nil
				}
				u.log("tsl: download failed", "url", loc, "attempt", i+1, "err", err)
				if ctx.Err() != nil {
					return nil, fmt.Errorf("tsl: %v: %w", ctx.Err(), ErrDownload)
				}
			}
		}
	}
	return nil, fmt.Errorf("tsl: no download address delivered the TSL: %w", ErrDownload)
}

func (u *Updater) get(ctx context.Context, url string, limit int64) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	client := u.Client
	if client == nil {
		client = defaultClient
	}
	res, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d", res.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(res.Body, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, errors.New("response too large")
	}
	return data, nil
}

// Import checks a new TSL, downloaded or brought in by hand, and makes it
// the trust space (TUC_PKI_001 steps 2 to 7): schema (TUC_PKI_020), signer
// certificate (TUC_PKI_011) against the active trust anchor, after
// activating an announced anchor whose StatusStartingTime has come
// (TUC_PKI_013 step 6), XML signature (TUC_PKI_012), ID and sequence
// number (TUC_PKI_019 steps 5 and 6), the signer's OCSP status (step 4),
// and new announced anchors (TUC_PKI_013). It reports whether the trust
// space changed; a TSL with the ID and sequence number of the current one
// changes nothing.
func (u *Updater) Import(ctx context.Context, data []byte) (bool, error) {
	u.mu.Lock()
	cur, anchor, future, futureStart, futureService := u.cur, u.anchor, u.future, u.futureStart, u.futureService
	u.mu.Unlock()
	if cur == nil {
		return false, ErrNoTrustSpace
	}
	now := u.now()
	t, err := Parse(data)
	if err != nil {
		return false, err
	}
	var announcer *Service
	if future != nil && !now.Before(futureStart) {
		anchor, announcer = future, futureService
	}
	signer, err := t.Verify(VerifyOptions{TrustAnchors: []*x509.Certificate{anchor}, Time: now})
	if err != nil {
		return false, err
	}
	switch {
	case t.ID == cur.ID && t.SequenceNumber == cur.SequenceNumber:
		u.mu.Lock()
		if u.cur == cur {
			u.hash = sum(data)
		}
		u.mu.Unlock()
		u.log("tsl: same TSL", "seq", t.SequenceNumber)
		return false, nil
	case t.ID == cur.ID || t.SequenceNumber <= cur.SequenceNumber:
		return false, fmt.Errorf("tsl: new TSL %d (%s) is not newer than TSL %d (%s): %w", t.SequenceNumber, t.ID, cur.SequenceNumber, cur.ID, ErrID)
	}
	if u.OCSP != nil {
		if err := checkSigner(ctx, u.OCSP, cur, signer, anchor, announcer); err != nil {
			return false, err
		}
	}
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.cur != cur {
		return false, errors.New("tsl: the trust space changed during the import")
	}
	if announcer != nil {
		u.anchor, u.future, u.futureService = anchor, nil, nil
		u.log("tsl: trust anchor activated", "subject", anchor.Subject.String())
	}
	u.cur, u.hash = t, sum(data)
	u.announce(t)
	u.log("tsl: trust space updated", "seq", t.SequenceNumber, "id", t.ID)
	return true, nil
}

// checkSigner asks the OCSP responder about the new TSL's signer, with
// the address and responders of cur, the TSL in the system (TUC_PKI_001
// step 4 and note): the address of the service that lists the anchor, or,
// the first time after an anchor change, of the TSLServiceCertChange
// entry announcer that announced it.
func checkSigner(ctx context.Context, c *ocsp.Checker, cur *TSL, signer, anchor *x509.Certificate, announcer *Service) error {
	svc := announcer
	if svc == nil {
		svc = cur.ServiceOf(TypeCA, anchor)
	}
	loc := ""
	if svc != nil {
		loc = svc.OCSPLocation()
	}
	if _, _, err := c.Check(ctx, signer, anchor, loc, cur.OCSPResponders()); err != nil {
		return fmt.Errorf("tsl: TSL signer %q: %w", signer.Subject, err)
	}
	return nil
}

// announce records the trust anchor t announces, if any (TUC_PKI_013).
// Only the latest announcement counts; errors keep the previous state and
// are logged (step "Fehlerfälle": an abort only means no new anchor).
func (u *Updater) announce(t *TSL) {
	c, start, err := t.AnnouncedTrustAnchor()
	switch {
	case err != nil:
		u.log("tsl: announced trust anchor ignored", "err", err)
	case c == nil:
	case c.Equal(u.anchor):
	default:
		u.future, u.futureStart = c, start
		u.futureService = t.ServicesOfType(TypeTSLServiceCertChg)[0]
		u.log("tsl: trust anchor announced", "subject", c.Subject.String(), "start", start)
	}
}
