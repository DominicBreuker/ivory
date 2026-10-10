package tsl

import (
	"testing"
	"time"

	"github.com/DominicBreuker/ivory/internal/tsltest"
)

// FuzzParse parses arbitrary TSLs: Parse and the accessors must never
// panic, and Verify without trust anchors must never succeed.
func FuzzParse(f *testing.F) {
	next := time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
	f.Add([]byte(tsltest.XML(10001, next, "http://tsl.example/tsl.xml", "http://tsl.example/tsl-backup.xml",
		tsltest.Service{Type: TypeCA, SupplyPoints: []string{"http://ocsp.example"}, ExtensionOIDs: []string{"1.2.276.0.76.4.77"}},
		tsltest.Service{Type: TypeTSLServiceCertChg, Status: StatusRevoked})))
	f.Add([]byte(`<TrustServiceStatusList xmlns="http://uri.etsi.org/02231/v2#" TSLTag="http://uri.etsi.org/02231/TSLTag"/>`))
	f.Fuzz(func(t *testing.T, data []byte) {
		l, err := Parse(data)
		if err != nil {
			return
		}
		l.CAs()
		l.OCSPResponders()
		l.AnnouncedTrustAnchor()
		l.SignerCertificate()
		for _, s := range l.Services {
			s.OCSPLocation()
		}
		if _, err := l.Verify(VerifyOptions{Time: next}); err == nil {
			t.Fatal("verified without trust anchors")
		}
	})
}
