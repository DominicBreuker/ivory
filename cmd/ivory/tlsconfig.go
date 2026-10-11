//go:build ivory

package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"slices"
	"strings"

	"github.com/DominicBreuker/ivory/brainpool"
	"github.com/DominicBreuker/ivory/cmd/ivory/internal/wire"
	"github.com/DominicBreuker/ivory/ti"
	"github.com/DominicBreuker/ivory/tlsutil"
)

// tlsFlags select what the local side offers.
type tlsFlags struct {
	profile                 string
	versions                string
	suites, groups, sigalgs string
	alpn                    string
}

const profileHelp = `TLS profile:
  ti     TLS 1.2 with the TI cipher suites and groups (P-256, P-384,
         brainpoolP256r1, brainpoolP384r1), as the ivory ti presets
  tls13  TLS 1.3 with the Brainpool groups and signature schemes of
         RFC 8734 and the NIST curves
  wide   TLS 1.2 and 1.3 with everything crypto/tls and ivory support`

func (f *tlsFlags) register(fs *flag.FlagSet) {
	fs.StringVar(&f.profile, "profile", "ti", "`profile`: ti, tls13 or wide (see -help)")
	fs.StringVar(&f.versions, "tls", "", "TLS versions instead of the profile's: 1.2, 1.3 or 1.2-1.3")
	fs.StringVar(&f.suites, "suites", "", "comma-separated TLS 1.2 cipher suites (names or 0x hex) instead of the profile's")
	fs.StringVar(&f.groups, "groups", "", "comma-separated groups (names such as brainpoolP256r1, secp256r1, or numbers) instead of the profile's")
	fs.StringVar(&f.sigalgs, "sigalgs", "", "comma-separated signature schemes (names or 0x hex) to advertise instead of the profile's")
	fs.StringVar(&f.alpn, "alpn", "", "comma-separated ALPN protocols to offer")
}

// allBrainpool are the Brainpool curves.
var allBrainpool = []brainpool.Curve{brainpool.P256r1(), brainpool.P384r1(), brainpool.P512r1()}

// defaultSchemes are crypto/tls's signature schemes plus the TLS 1.3
// Brainpool schemes.
var defaultSchemes = []tls.SignatureScheme{
	tls.PSSWithSHA256, tls.ECDSAWithP256AndSHA256, tls.Ed25519,
	tls.PSSWithSHA384, tls.PSSWithSHA512,
	tls.PKCS1WithSHA256, tls.PKCS1WithSHA384, tls.PKCS1WithSHA512,
	tls.ECDSAWithP384AndSHA384, tls.ECDSAWithP521AndSHA512,
	tlsutil.ECDSABrainpoolP256r1TLS13SHA256, tlsutil.ECDSABrainpoolP384r1TLS13SHA384, tlsutil.ECDSABrainpoolP512r1TLS13SHA512,
}

// config returns the configuration for the flags, without identities or
// certificate checks.
func (f *tlsFlags) config() (*tls.Config, error) {
	c := &tls.Config{
		VerifyUnsupportedSignature: tlsutil.VerifyUnsupportedSignature,
		KeyExchanges:               tlsutil.KeyExchanges(allBrainpool...),
	}
	switch f.profile {
	case "ti":
		c.MinVersion, c.MaxVersion = tls.VersionTLS12, tls.VersionTLS12
		c.CipherSuites = slices.Concat(ti.SuitesECDSA, ti.SuitesRSA)
		c.CurvePreferences = slices.Clone(ti.Curves)
	case "tls13":
		c.MinVersion, c.MaxVersion = tls.VersionTLS13, tls.VersionTLS13
		c.CurvePreferences = []tls.CurveID{
			tlsutil.CurveBrainpoolP256r1TLS13, tlsutil.CurveBrainpoolP384r1TLS13, tlsutil.CurveBrainpoolP512r1TLS13,
			tls.CurveP256, tls.CurveP384,
		}
		c.SignatureSchemes = tlsutil.SignatureSchemes()
	case "wide":
		c.MinVersion, c.MaxVersion = tls.VersionTLS12, tls.VersionTLS13
		c.CurvePreferences = []tls.CurveID{
			tls.X25519MLKEM768, tls.X25519, tls.CurveP256, tls.CurveP384, tls.CurveP521,
			tlsutil.CurveBrainpoolP256r1TLS13, tlsutil.CurveBrainpoolP384r1TLS13, tlsutil.CurveBrainpoolP512r1TLS13,
			tlsutil.CurveBrainpoolP256r1, tlsutil.CurveBrainpoolP384r1, tlsutil.CurveBrainpoolP512r1,
		}
		c.SignatureSchemes = slices.Clone(defaultSchemes)
	default:
		return nil, fmt.Errorf("-profile: unknown profile %q (ti, tls13 or wide)", f.profile)
	}
	switch f.versions {
	case "":
	case "1.2":
		c.MinVersion, c.MaxVersion = tls.VersionTLS12, tls.VersionTLS12
	case "1.3":
		c.MinVersion, c.MaxVersion = tls.VersionTLS13, tls.VersionTLS13
	case "1.2-1.3":
		c.MinVersion, c.MaxVersion = tls.VersionTLS12, tls.VersionTLS13
	default:
		return nil, fmt.Errorf("-tls: want 1.2, 1.3 or 1.2-1.3, not %q", f.versions)
	}
	if c.MaxVersion == tls.VersionTLS13 && c.SignatureSchemes == nil {
		// A TLS 1.3 peer needs the Brainpool schemes to use a Brainpool
		// certificate.
		c.SignatureSchemes = slices.Clone(defaultSchemes)
	}
	var err error
	if f.suites != "" {
		if c.CipherSuites, err = parseList(f.suites, func(s string) (uint16, bool) {
			v, ok := wire.ParseCipherSuite(s)
			return uint16(v), ok
		}); err != nil {
			return nil, fmt.Errorf("-suites: %w", err)
		}
	}
	if f.groups != "" {
		ids, err := parseList(f.groups, func(s string) (uint16, bool) {
			v, ok := wire.ParseGroup(s)
			return uint16(v), ok
		})
		if err != nil {
			return nil, fmt.Errorf("-groups: %w", err)
		}
		c.CurvePreferences = nil
		for _, id := range ids {
			c.CurvePreferences = append(c.CurvePreferences, tls.CurveID(id))
		}
	}
	if f.sigalgs != "" {
		ids, err := parseList(f.sigalgs, func(s string) (uint16, bool) {
			v, ok := wire.ParseSignatureScheme(s)
			return uint16(v), ok
		})
		if err != nil {
			return nil, fmt.Errorf("-sigalgs: %w", err)
		}
		c.SignatureSchemes = nil
		for _, id := range ids {
			c.SignatureSchemes = append(c.SignatureSchemes, tls.SignatureScheme(id))
		}
	}
	if f.alpn != "" {
		c.NextProtos = strings.Split(f.alpn, ",")
	}
	return c, nil
}

func parseList(s string, parse func(string) (uint16, bool)) ([]uint16, error) {
	var out []uint16
	for _, item := range strings.Split(s, ",") {
		if item = strings.TrimSpace(item); item == "" {
			continue
		}
		v, ok := parse(item)
		if !ok {
			return nil, fmt.Errorf("unknown value %q", item)
		}
		out = append(out, v)
	}
	return out, nil
}
