//go:build ivory

package tsl

// A regression corpus of real TSLs: every production, reference and test
// TSL archived since 2025-04 and the TSLs shipped with ZETA Guard,
// downloaded by scripts/fetch-tsl-corpus.sh into $IVORY_TSL_CORPUS (the
// test is skipped without it, unless $IVORY_REQUIRE_TSL_CORPUS is set).
// Each TSL must parse, verify against its environment's trust anchor at
// its issue date, and the TSLs of each environment must follow each other
// through the Updater. The TSLs in invalid/ were changed after signing
// and must fail.

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/DominicBreuker/ivory/brainpool"
	"github.com/DominicBreuker/ivory/x509util"
)

// corpusEnvs are the environments of the corpus with the SHA-256
// fingerprints of their trust anchors, GEM.TSL-CA3 and GEM.TSL-CA28
// TEST-ONLY (the same pins as scripts/fetch-production-tsl.sh), and the
// number of TSLs in tsl/testdata/tsl-corpus.sha256.
var corpusEnvs = []struct {
	env, anchor string
	n           int
}{
	{"prod", "e2992dc292f6aa8d9e462a7723f54c162853b4056c277260b82ce58921408448", 38},
	{"ref", "43853a0e92bfd6e9e99f02c1d165a688aa94f0df74d8ea0ddf849ecd01be1d6a", 49},
	{"test", "43853a0e92bfd6e9e99f02c1d165a688aa94f0df74d8ea0ddf849ecd01be1d6a", 48},
}

// invalidTSLs are the TSLs in invalid/ and their anchors' fingerprints.
var invalidTSLs = map[string]string{
	// ZETA Guard's test TSL 10691 (zeta-guard-provisioning/test/tsl/
	// ECC_TU_TSL_10691.xml), indented after signing.
	"db538278a19f181c94de8d81d66d68c06072e3853fa5978d2107e22288185642.xml": "43853a0e92bfd6e9e99f02c1d165a688aa94f0df74d8ea0ddf849ecd01be1d6a",
}

func TestTSLCorpus(t *testing.T) {
	dir := os.Getenv("IVORY_TSL_CORPUS")
	if dir == "" {
		if os.Getenv("IVORY_REQUIRE_TSL_CORPUS") != "" {
			t.Fatal("IVORY_TSL_CORPUS is not set (scripts/fetch-tsl-corpus.sh)")
		}
		t.Skip("IVORY_TSL_CORPUS is not set (scripts/fetch-tsl-corpus.sh)")
	}
	for _, e := range corpusEnvs {
		t.Run(e.env, func(t *testing.T) {
			files, err := filepath.Glob(filepath.Join(dir, e.env, "*.xml"))
			if err != nil {
				t.Fatal(err)
			}
			if len(files) != e.n {
				t.Fatalf("%d TSLs, want %d (scripts/fetch-tsl-corpus.sh)", len(files), e.n)
			}
			var tsls []*TSL
			var anchor *x509.Certificate
			for _, f := range files {
				data, err := os.ReadFile(f)
				if err != nil {
					t.Fatal(err)
				}
				l, err := Parse(data)
				if err != nil {
					t.Errorf("%s: %v", filepath.Base(f), err)
					continue
				}
				// The TSL lists its own trust anchor as a CA service; the
				// pinned fingerprint picks it.
				a := corpusAnchor(l, e.anchor)
				if a == nil {
					t.Errorf("TSL %d doesn't list the trust anchor %s", l.SequenceNumber, e.anchor)
					continue
				}
				anchor = a
				checkCorpusTSL(t, l, a)
				tsls = append(tsls, l)
			}
			if t.Failed() {
				return
			}
			replayCorpus(t, tsls, anchor)
		})
	}
	t.Run("invalid", func(t *testing.T) {
		files, err := filepath.Glob(filepath.Join(dir, "invalid", "*.xml"))
		if err != nil {
			t.Fatal(err)
		}
		if len(files) != len(invalidTSLs) {
			t.Fatalf("%d TSLs, want %d (scripts/fetch-tsl-corpus.sh)", len(files), len(invalidTSLs))
		}
		for _, f := range files {
			data, err := os.ReadFile(f)
			if err != nil {
				t.Fatal(err)
			}
			l, err := Parse(data)
			if err != nil {
				t.Fatalf("%s: %v", filepath.Base(f), err)
			}
			a := corpusAnchor(l, invalidTSLs[filepath.Base(f)])
			if a == nil {
				t.Fatalf("TSL %d doesn't list its trust anchor", l.SequenceNumber)
			}
			if _, err := l.Verify(VerifyOptions{TrustAnchors: []*x509.Certificate{a}, Time: l.IssueDate}); !errors.Is(err, ErrSignature) {
				t.Errorf("TSL %d: %v, want ErrSignature", l.SequenceNumber, err)
			}
		}
	})
}

func corpusAnchor(l *TSL, fingerprint string) *x509.Certificate {
	for _, s := range l.Services {
		for _, c := range s.ParsedCertificates() {
			if sum := sha256.Sum256(c.Raw); hex.EncodeToString(sum[:]) == fingerprint {
				return c
			}
		}
	}
	return nil
}

// checkCorpusTSL checks one TSL as of its issue date.
func checkCorpusTSL(t *testing.T, l *TSL, anchor *x509.Certificate) {
	t.Helper()
	signer, err := l.Verify(VerifyOptions{TrustAnchors: []*x509.Certificate{anchor}, Time: l.IssueDate})
	if err != nil {
		t.Errorf("TSL %d: %v", l.SequenceNumber, err)
		return
	}
	if pub, err := x509util.PublicKey(signer); err != nil {
		t.Errorf("TSL %d: %v", l.SequenceNumber, err)
	} else if bp, ok := pub.(*brainpool.PublicKey); !ok || bp.Curve() != brainpool.P256r1() {
		t.Errorf("TSL %d: signer key %T, want brainpoolP256r1", l.SequenceNumber, pub)
	}
	n, parsed := 0, 0
	for _, s := range l.Services {
		n += len(s.Certificates)
		parsed += len(s.ParsedCertificates())
	}
	if parsed != n || len(l.CAs()) == 0 || len(l.OCSPResponders()) == 0 {
		t.Errorf("TSL %d: %d of %d certificates parse; %d CAs, %d OCSP responders", l.SequenceNumber, parsed, n, len(l.CAs()), len(l.OCSPResponders()))
	}
	if len(l.PrimaryLocations) == 0 || len(l.BackupLocations) == 0 {
		t.Errorf("TSL %d: download addresses %v %v", l.SequenceNumber, l.PrimaryLocations, l.BackupLocations)
	}
	if l.NextUpdate.IsZero() || !l.NextUpdate.After(l.IssueDate) {
		t.Errorf("TSL %d: issued %v, next update %v", l.SequenceNumber, l.IssueDate, l.NextUpdate)
	}
	if _, _, err := l.AnnouncedTrustAnchor(); err != nil {
		t.Errorf("TSL %d: %v", l.SequenceNumber, err)
	}
}

// replayCorpus feeds an environment's TSLs to an Updater in the order of
// their sequence numbers, each at its issue date, without OCSP (offline
// mode): each is accepted as newer than the one before; a copy with the
// same ID and sequence number changes nothing; going back is refused.
func replayCorpus(t *testing.T, tsls []*TSL, anchor *x509.Certificate) {
	t.Helper()
	slices.SortStableFunc(tsls, func(a, b *TSL) int { return int(a.SequenceNumber - b.SequenceNumber) })
	var now time.Time
	u := &Updater{Time: func() time.Time { return now }}
	now = tsls[0].IssueDate
	if err := u.Init(tsls[0].Raw, anchor); err != nil {
		t.Fatalf("Init with TSL %d: %v", tsls[0].SequenceNumber, err)
	}
	ctx := context.Background()
	for i, l := range tsls[1:] {
		prev := tsls[i]
		now = l.IssueDate
		changed, err := u.Import(ctx, l.Raw)
		same := l.ID == prev.ID && l.SequenceNumber == prev.SequenceNumber
		if err != nil || changed == same {
			t.Errorf("Import TSL %d after %d: changed %v, %v", l.SequenceNumber, prev.SequenceNumber, changed, err)
		}
	}
	last := tsls[len(tsls)-1]
	if u.Current().SequenceNumber != last.SequenceNumber {
		t.Errorf("current TSL %d, want %d", u.Current().SequenceNumber, last.SequenceNumber)
	}
	if prev := tsls[len(tsls)-2]; prev.SequenceNumber < last.SequenceNumber {
		if _, err := u.Import(ctx, prev.Raw); !errors.Is(err, ErrID) {
			t.Errorf("Import of TSL %d after %d: %v, want ErrID", prev.SequenceNumber, last.SequenceNumber, err)
		}
	}
}
