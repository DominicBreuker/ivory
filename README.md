# ivory

ivory lets Go programs use **Brainpool** certificates and Brainpool key
exchange in TLS, as the German health care telematics infrastructure (TI,
specified by gematik) requires. It keeps Go's own `crypto/tls` and
`crypto/x509`: it doesn't reimplement TLS or X.509, it opens them.

- TLS 1.2 and TLS 1.3 with brainpoolP256r1, brainpoolP384r1 and
  brainpoolP512r1: certificates, signatures (RFC 7027, RFC 8734) and key
  exchange groups.
- Brainpool keys in software or on a smart card (any `crypto.Signer`).
- `tls.Config` presets for TI roles, including the eHealth card terminal
  (KT) and Konnektor-like clients.
- The TSL and OCSP as gematik's PKI checks need them: TSL signatures
  (brainpoolP256r1, XMLDSig), the trust space update, and OCSP responses
  signed by Brainpool responders; an example server passes gematik's
  PKI test suite (all 111 tests of its KIM Fachdienst profile).
- [`ivory`](cmd/ivory), a command-line TLS test tool (experimental):
  connect to TI products, accept their connections and probe what they
  support, with decoded handshake traces; and local tunnels that give
  curl and other tools without Brainpool support Brainpool TLS.
- Tested against OpenSSL 3.0 and 3.5, BouncyCastle's TLS provider for
  Java, Windows SChannel (TLS 1.2) and Go itself, with Go's own
  `crypto/tls` and `crypto/x509` test suites, BoringSSL's BoGo,
  tlsfuzzer, x509-limbo, Wycheproof, the RFC and Botan Brainpool test
  vectors, and fuzzing.

> **Status: v0.3.** ivory has had a careful self-review, not an external
> security review, and hasn't been tested against real TI products yet.
> APIs may change before v1.0. Please read
> [docs/security.md](docs/security.md) before you rely on it, and
> [tell us](#feedback) how it works with your peers.

## How it works

ivory has two parts:

1. **The overlay:** a short series of patches to Go's `crypto/x509` and
   `crypto/tls`, applied at build time to a pinned Go release with
   `go build -overlay` (or written into a patched copy of GOROOT). The
   patches open the places where Go rejects keys and groups it doesn't
   implement. They contain no Brainpool math and no Brainpool names, and
   are written so that they can be proposed to the Go project.
2. **The library:** Go packages that plug Brainpool into those openings.

| Package | What | Needs the overlay |
|---|---|---|
| [`brainpool`](brainpool) | brainpoolP256r1, P384r1, P512r1: ECDSA, ECDH, key generation, in constant time | no |
| [`x509util`](x509util) | Brainpool keys in PKIX, PKCS #8 and SEC 1; certificate, CSR and CRL signatures by Brainpool keys | no (Brainpool *certificates* parse only with the overlay) |
| [`tlsutil`](tlsutil) | `crypto/tls` hooks: Brainpool groups, signature verification, signers (software keys and smart cards), certificate selection | yes |
| [`ti`](ti) | `tls.Config` presets and certificate checks for TI roles | yes |
| [`tsl`](tsl) | the TI's TSL: schema, XML signature, signer, trust space update, CA status for certificate checks | no (Brainpool certificates in the TSL parse only with the overlay) |
| [`ocsp`](ocsp) | OCSP requests and responses with Brainpool, NIST and RSA responders; the checks of gemSpec_PKI | no (likewise) |

The overlay comes in two profiles:

| Profile | Patches | For |
|---|---|---|
| `core` | P0–P5 | every program |
| `kt` | `core` plus P6 and P7, behaviors that only an eHealth card terminal (KT) needs | the KT only |

## Quick start

You need linux/amd64 (the only tested platform), bash, git, and any Go ≥
1.22. That Go only builds the overlay tool, which downloads the Go release
ivory pins (from proxy.golang.org, verified by the Go checksum database).

```sh
git clone https://github.com/DominicBreuker/ivory ~/ivory
cd ~/ivory
scripts/ivory-overlay toolchain              # download the pinned Go release
scripts/ivory-overlay build -profile core    # check it and build the overlay
scripts/ivory-overlay doctor -profile core   # check the result
```

Then use it from your own module. `env` puts the pinned Go on PATH and
sets `GOFLAGS="-overlay=… -tags=ivory,ivory_core"` and
`GOTOOLCHAIN=local`:

```sh
mkdir ~/tlsdemo && cd ~/tlsdemo
eval "$(~/ivory/scripts/ivory-overlay env -profile core)"
go mod init example.com/tlsdemo
go get github.com/DominicBreuker/ivory@v0.3.0   # the version of your ivory checkout
# A Brainpool test identity and its CA from ivory's test PKI:
cp ~/ivory/testdata/pki/bp256-server.pem server.pem
cp ~/ivory/testdata/pki/bp256-server.key server.key
cp ~/ivory/testdata/pki/bp256-ca.pem ca.pem
```

`main.go` starts a TI TLS server with the Brainpool identity and connects
to it with a TI client that checks the server against the stored CA
certificate:

<!-- quickstart:begin -->
```go
//go:build ivory

package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"os"

	"github.com/DominicBreuker/ivory/ti"
	"github.com/DominicBreuker/ivory/tlsutil"
)

func main() {
	// A Brainpool identity: certificate and PKCS #8 or SEC 1 key. For a key
	// on a smart card, use tlsutil.Certificate with tlsutil.RawSigner.
	cert, err := tlsutil.LoadX509KeyPair("server.pem", "server.key")
	if err != nil {
		log.Fatal(err)
	}
	server := ti.ServerConfig([]tls.Certificate{cert}, nil) // nil: no client certificates
	ln, err := tls.Listen("tcp", "127.0.0.1:0", server)
	if err != nil {
		log.Fatal(err)
	}
	go func() {
		c, err := ln.Accept()
		if err != nil {
			log.Fatal(err)
		}
		defer c.Close()
		io.WriteString(c, "hello over Brainpool TLS\n")
	}()

	// The client checks the server's certificate against stored CA
	// certificates, the way TI products do.
	client := ti.ClientConfig(nil, &ti.Verifier{CAs: []*x509.Certificate{readCert("ca.pem")}})
	client.ServerName = "localhost"
	conn, err := tls.Dial("tcp", ln.Addr().String(), client)
	if err != nil {
		log.Fatal(err)
	}
	defer conn.Close()
	msg, err := io.ReadAll(conn)
	if err != nil {
		log.Fatal(err)
	}
	cs := conn.ConnectionState()
	fmt.Printf("%s, %s, server %q\n%s", tls.VersionName(cs.Version),
		tls.CipherSuiteName(cs.CipherSuite), cs.PeerCertificates[0].Subject.CommonName, msg)
}

func readCert(file string) *x509.Certificate {
	data, err := os.ReadFile(file)
	if err != nil {
		log.Fatal(err)
	}
	block, _ := pem.Decode(data)
	if block == nil {
		log.Fatalf("%s: no PEM data", file)
	}
	// With the overlay, crypto/x509 parses Brainpool certificates; their
	// signatures are checked by ti.Verifier (package x509util).
	c, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		log.Fatal(err)
	}
	return c
}
```
<!-- quickstart:end -->

```sh
$ go run .
TLS 1.2, TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, server "localhost"
hello over Brainpool TLS
```

Next: [docs/user-guide.md](docs/user-guide.md) (smart cards, the KT
preset, TLS 1.3, TSL and OCSP, editors, CI), and the runnable examples
[examples/ktserver](examples/ktserver),
[examples/connectorclient](examples/connectorclient) and
[examples/fachdienst](examples/fachdienst): the comment at the top of
each `main.go` shows how to run it. To try Brainpool TLS without writing
code, build the [`ivory` tool](cmd/ivory/README.md#first-steps).

### The `ivory` build tag

Code that uses API added by the overlay, or the packages `tlsutil` and
`ti`, starts with `//go:build ivory`. `ivory-overlay env` adds
`-tags=ivory,ivory_<profile>` to GOFLAGS. With the tag but without the
overlay, the build fails with an unknown-field error, the signal to build
the overlay; without the tag, such files are left out.

## Supported Go versions

| Go release | Overlay profiles | Status |
|---|---|---|
| go1.27.2 | core, kt | pinned |

Each ivory version supports exactly one Go release, the one in
`overlay/GOVERSION`. New Go patch releases are adopted with
`scripts/ivory-overlay adopt`, which fetches the release, rebases the
patches, re-pins and runs the test suite; ivory then publishes a new
version. Older Go releases stay usable with older ivory versions.

## Patches

[overlay/README.md](overlay/README.md) describes each patch, its tests,
and the plan to propose P0–P5 to the Go project.

| Patch | Concern | Profiles |
|---|---|---|
| P0 | a TLS server refuses renegotiation with a fatal `no_renegotiation` alert | core, kt |
| P1 | crypto/x509 parses keys on unsupported named curves (`Verify` results unchanged) | core, kt |
| P2 | `Config.VerifyUnsupportedSignature`: peer signatures by keys crypto/tls doesn't support | core, kt |
| P3 | crypto/tls signs with opaque public-key types (`Certificate.SupportedSignatureAlgorithms`) | core, kt |
| P4 | `Config.KeyExchanges`: external key-exchange groups | core, kt |
| P5 | `Config.SignatureSchemes`: advertise signature schemes crypto/tls doesn't implement (TLS 1.3; provisional API) | core, kt |
| P6 | one CertificateRequest certificate type per suite (gemSpec_KT A_22454) | kt |
| P7 | a client offers ECDSA suites before RSA suites (gemSpec_Krypt A_17124-03) | kt |

Without the new `tls.Config` fields, a patched `crypto/tls` behaves like
Go's, except for P0 (and P6, P7 in the profile `kt`). Every hook is
opt-in, fails closed, and is off in FIPS 140-3 mode.

## Testing

CI ([.github/workflows](.github/workflows)) runs on every push to `main`
(the Windows job on demand):

- Go's own `crypto/x509` and `crypto/tls` tests under the overlay, for
  both profiles, including the tests each patch adds; `go vet` of both
  packages for windows and darwin too;
- ivory's tests with and without the overlay: Wycheproof ECDSA and ECDH
  vectors for all three curves, the ECDH test vectors of RFC 7027 (and
  RFC 8734) and RFC 6932, Botan's point multiplication and RFC 6979
  vectors, test vectors from gemSpec_Krypt,
  differential tests against an independent implementation, OpenSSL and
  Python `cryptography`;
- the interop matrix against OpenSSL 3.0 (TLS 1.2), OpenSSL 3.5 (TLS
  1.3), BouncyCastle's JSSE provider 1.86 (TLS 1.2 and 1.3), and Go ↔ Go
  ([interop/README.md](interop/README.md));
- tlsfuzzer's Brainpool scripts and its ECDSA scripts with Brainpool
  identities against ivory servers (F1–F6 in
  [interop/README.md](interop/README.md));
- Windows SChannel through .NET's `SslStream` on Windows Server 2025
  (on demand), both roles (S1–S7: TLS 1.2 works; SChannel's TLS 1.3
  isn't RFC 8734; `tlsutil.TLS12Fallback` for servers that also offer
  TLS 1.3);
- `tsl` against 136 archived production, reference and test TSLs;
- wire probes of what crypto/tls sends ([probe/README.md](probe/README.md));
- BoGo's renegotiation tests.

Nightly: the full BoGo suite for both profiles, non-short `crypto/x509`
(x509-limbo, NIST PKITS), and the patches on Go's development branch. On
demand: every fuzz target (1 hour each by default), and gematik's PKI
test suite against `examples/fachdienst` (`pkits.yml`, about 80
minutes); every night also today's production, reference and test TSLs
against their trust anchors (`scripts/fetch-production-tsl.sh`).
[docs/brainpool-constant-time.md](docs/brainpool-constant-time.md) is the
constant-time review of the Brainpool code.

## Documentation

- [docs/user-guide.md](docs/user-guide.md): the overlay or a materialized
  GOROOT, your own module, TLS 1.2 for the TI, TLS 1.3 with Brainpool,
  TSL and OCSP, the test tool, editors, CI, new Go releases,
  troubleshooting.
- [docs/security.md](docs/security.md): what the patches change, what is
  constant time, random numbers, erasure of secrets, protocol choices,
  the TSL and OCSP checks, what the test tool trusts.
- [docs/compliance.md](docs/compliance.md): TI requirements, the
  mechanism that meets each, and its tests.
- [cmd/ivory/README.md](cmd/ivory/README.md): `ivory`, the test tool
  (experimental): connect to TI products, accept their connections,
  probe what they support, with handshake traces; a local tunnel and
  HTTP proxy that give other tools, such as curl, Brainpool TLS; and a
  reverse tunnel that gives other servers Brainpool TLS.
- [CHANGELOG.md](CHANGELOG.md): what changed in each version.

## Feedback

ivory needs reports from real deployments: which TI products (Konnektor,
card terminals, Fachdienste, test tools) it works with, and which it
doesn't. Please open an issue with the "Interop report" template, or a
bug report. Security problems: see [SECURITY.md](SECURITY.md); please
don't open a public issue for them. [CONTRIBUTING.md](CONTRIBUTING.md)
explains how changes are made.

## Repository layout

| Path | Contents |
|---|---|
| `brainpool/`, `x509util/`, `tlsutil/`, `ti/`, `tsl/`, `ocsp/` | the library |
| `internal/` | XML canonicalization and signatures for `tsl`; test helpers |
| `overlay/` | patches, profiles, pinned file hashes, and the patch documentation |
| `cmd/ivory-overlay/` | the overlay tool: fetch the toolchain, check pins, build the overlay or a patched GOROOT, test, adopt new Go releases (a module of its own, so that any Go ≥ 1.22 builds it) |
| `scripts/` | `ivory-overlay` (builds and runs the tool), `gen-testpki.sh` (the test PKI), `build-openssl.sh` (OpenSSL from source for the TLS 1.3 tests), `fetch-bouncycastle.sh` (the BouncyCastle jars for the Java interop tests), `fetch-gemlibpki.sh` (certificates and TSLs of the TI test PKI for the `ti` and `tsl` tests), `run-pkits.sh` (gematik's PKI test suite against `examples/fachdienst`), `fetch-production-tsl.sh` (today's production, reference or test TSL and its trust anchor), `fetch-tsl-corpus.sh` (archived TSLs for the `tsl` tests), `fetch-tlsfuzzer.sh` (tlsfuzzer for the interop tests F1–F6) |
| `cmd/ivory/` | `ivory` (experimental), a TLS test client, server and prober for TI products, with handshake traces and the TI check of peer certificates, a tunnel and HTTP proxy that give other tools Brainpool TLS, and a reverse tunnel for other servers |
| `examples/` | a card terminal server, a Konnektor-like client, and a TI server that checks clients against the TSL with OCSP |
| `interop/`, `probe/` | interop tests and wire probes |
| `testdata/pki/` | test certificates and keys (Brainpool, P-256, RSA); test only |
| `docs/` | user documentation |

## License

BSD-3-Clause, like Go; see [LICENSE](LICENSE). The overlay patches modify
Go source files, which stay under Go's license (Copyright The Go Authors).
