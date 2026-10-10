//go:build ivory

package tsl

// Test TSLs of gematik's TI test PKI, as published with gematik's
// reference PKI library GemLibPki: TSLs signed with brainpoolP256r1 by
// "TSL Signing Unit 51 TEST-ONLY" under the trust anchor GEM.TSL-CA51, and
// GemLibPki's invalid and defect variants. They are downloaded by
// scripts/fetch-gemlibpki.sh into $IVORY_GEMLIBPKI; the test is skipped
// without it, unless $IVORY_REQUIRE_GEMLIBPKI is set.

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestGemLibPki(t *testing.T) {
	dir := os.Getenv("IVORY_GEMLIBPKI")
	if dir == "" {
		if os.Getenv("IVORY_REQUIRE_GEMLIBPKI") != "" {
			t.Fatal("IVORY_GEMLIBPKI is not set (scripts/fetch-gemlibpki.sh)")
		}
		t.Skip("IVORY_GEMLIBPKI is not set (scripts/fetch-gemlibpki.sh)")
	}
	b, err := os.ReadFile(filepath.Join(dir, "GEM.TSL-CA51/GEM.TSL-CA51-TEST-ONLY.pem"))
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(b)
	anchor, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	load := func(t *testing.T, name string) (*TSL, error) {
		data, err := os.ReadFile(filepath.Join(dir, "tsls/nonqes", name))
		if err != nil {
			t.Fatal(err)
		}
		return Parse(data)
	}
	verify := func(l *TSL) error {
		_, err := l.Verify(VerifyOptions{TrustAnchors: []*x509.Certificate{anchor}, Time: l.IssueDate})
		return err
	}

	for _, name := range []string{"valid/TSL_default.xml", "valid/TSL_altCA_revoked.xml", "valid/TSL_TAchange.xml"} {
		t.Run(name, func(t *testing.T) {
			l, err := load(t, name)
			if err != nil {
				t.Fatal(err)
			}
			if err := verify(l); err != nil {
				t.Fatal(err)
			}
			// Every certificate of the TSL parses with the overlay, the
			// Brainpool ones included.
			for _, s := range l.Services {
				if len(s.ParsedCertificates()) != len(s.Certificates) {
					t.Errorf("service %q: %d of %d certificates parse", s.Name, len(s.ParsedCertificates()), len(s.Certificates))
				}
			}
			if len(l.CAs()) == 0 || len(l.OCSPResponders()) == 0 || len(l.PrimaryLocations) == 0 || len(l.BackupLocations) == 0 {
				t.Errorf("%d CAs, %d OCSP responders, locations %v %v", len(l.CAs()), len(l.OCSPResponders()), l.PrimaryLocations, l.BackupLocations)
			}
			ta, _, err := l.AnnouncedTrustAnchor()
			if err != nil || (name == "valid/TSL_TAchange.xml") != (ta != nil) {
				t.Errorf("announced trust anchor %v, %v", ta, err)
			}
			if ta != nil && ta.Subject.CommonName != "GEM.TSL-CA52 TEST-ONLY" {
				t.Errorf("announced trust anchor %s", ta.Subject)
			}
		})
	}
	t.Run("revoked CA", func(t *testing.T) {
		l, err := load(t, "valid/TSL_altCA_revoked.xml")
		if err != nil {
			t.Fatal(err)
		}
		n := 0
		for _, s := range l.ServicesOfType(TypeCA) {
			if s.Status == StatusRevoked {
				n++
			}
		}
		if n == 0 {
			t.Error("no revoked CA")
		}
	})
	t.Run("signature broken", func(t *testing.T) {
		l, err := load(t, "invalid/TSL_invalid_Signature_broken.xml")
		if err != nil {
			t.Fatal(err)
		}
		if err := verify(l); !errors.Is(err, ErrSignature) {
			t.Errorf("got %v, want ErrSignature", err)
		}
	})
	for _, name := range []string{"invalid/TSL_invalid_xmlNonEtsiTag_altCA.xml", "invalid/TSL_invalid_xmlNamespace_altCA.xml"} {
		t.Run(name, func(t *testing.T) {
			if _, err := load(t, name); err == nil {
				t.Error("schema violation not detected")
			}
		})
	}
	for name, want := range map[string]error{
		"defect/TSL_defect_TAchange_twoEntries.xml": ErrMultipleTrustAnchors,
		"defect/TSL_defect_TAchange_broken.xml":     ErrCertExtraction,
	} {
		t.Run(name, func(t *testing.T) {
			l, err := load(t, name)
			if err != nil {
				t.Fatal(err)
			}
			if _, _, err := l.AnnouncedTrustAnchor(); !errors.Is(err, want) {
				t.Errorf("got %v, want %v", err, want)
			}
		})
	}
}
