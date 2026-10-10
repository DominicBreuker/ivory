//go:build ivory

package tsl

// The current TSL of one of the TI's environments, verified against its
// trust anchor: the production TSL against GEM.TSL-CA3, the reference
// and test environments' TSLs against GEM.TSL-CA28 TEST-ONLY (both
// brainpoolP256r1). The files are downloaded by
// scripts/fetch-production-tsl.sh into $IVORY_PRODUCTION_TSL; the test
// checks each environment whose TSL it finds there. It is skipped without
// the variable, unless $IVORY_REQUIRE_PRODUCTION_TSL is set.

import (
	"crypto/x509"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/DominicBreuker/ivory/brainpool"
	"github.com/DominicBreuker/ivory/x509util"
)

// liveTSLs are the files scripts/fetch-production-tsl.sh writes.
var liveTSLs = []struct{ env, tsl, anchor string }{
	{"prod", "ECC-RSA_TSL.xml", "GEM.TSL-CA3.der"},
	{"ref", "ECC-RSA_TSL-ref.xml", "GEM.TSL-CA28_TEST-ONLY.der"},
	{"test", "ECC-RSA_TSL-test.xml", "GEM.TSL-CA28_TEST-ONLY.der"},
}

func TestProductionTSL(t *testing.T) {
	dir := os.Getenv("IVORY_PRODUCTION_TSL")
	if dir == "" {
		if os.Getenv("IVORY_REQUIRE_PRODUCTION_TSL") != "" {
			t.Fatal("IVORY_PRODUCTION_TSL is not set (scripts/fetch-production-tsl.sh)")
		}
		t.Skip("IVORY_PRODUCTION_TSL is not set (scripts/fetch-production-tsl.sh)")
	}
	found := 0
	for _, tt := range liveTSLs {
		data, err := os.ReadFile(filepath.Join(dir, tt.tsl))
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		found++
		t.Run(tt.env, func(t *testing.T) {
			if err != nil {
				t.Fatal(err)
			}
			der, err := os.ReadFile(filepath.Join(dir, tt.anchor))
			if err != nil {
				t.Fatal(err)
			}
			anchor, err := x509.ParseCertificate(der)
			if err != nil {
				t.Fatal(err)
			}
			checkLiveTSL(t, data, anchor)
		})
	}
	if found == 0 {
		t.Fatalf("no TSL in %s (scripts/fetch-production-tsl.sh)", dir)
	}
}

func checkLiveTSL(t *testing.T, data []byte, anchor *x509.Certificate) {
	l, err := Parse(data)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	signer, err := l.Verify(VerifyOptions{TrustAnchors: []*x509.Certificate{anchor}, Time: now})
	if err != nil {
		t.Fatalf("TSL %d: %v", l.SequenceNumber, err)
	}
	t.Logf("TSL %d (%s), issued %v, next update %v, signed by %q", l.SequenceNumber, l.ID, l.IssueDate, l.NextUpdate, signer.Subject)
	if pub, err := x509util.PublicKey(signer); err != nil {
		t.Error(err)
	} else if bp, ok := pub.(*brainpool.PublicKey); !ok || bp.Curve() != brainpool.P256r1() {
		t.Errorf("TSL signer key %T, want brainpoolP256r1", pub)
	}
	if l.Expired(now, 0) {
		t.Errorf("TSL %d expired at %v", l.SequenceNumber, l.NextUpdate)
	}
	if ta, start, err := l.AnnouncedTrustAnchor(); err != nil || ta != nil {
		t.Logf("the TSL announces a new trust anchor %v from %v (%v): update the pin in scripts/fetch-production-tsl.sh", ta, start, err)
	}
	// Every certificate of the TSL parses with the overlay.
	n, parsed := 0, 0
	for _, s := range l.Services {
		n += len(s.Certificates)
		parsed += len(s.ParsedCertificates())
	}
	if parsed != n || len(l.CAs()) == 0 || len(l.OCSPResponders()) == 0 {
		t.Errorf("%d of %d certificates parse; %d CAs, %d OCSP responders", parsed, n, len(l.CAs()), len(l.OCSPResponders()))
	}
	if len(l.PrimaryLocations) == 0 || len(l.BackupLocations) == 0 {
		t.Errorf("download addresses %v %v", l.PrimaryLocations, l.BackupLocations)
	}
}
