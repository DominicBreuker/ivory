# ivory user guide

This guide shows how to build Go programs with ivory: get the patched
toolchain, use it from your own module, write TLS 1.2 and TLS 1.3 code
with Brainpool keys and groups, set up editors and CI, and move to a new
Go release. [security.md](security.md) covers what ivory does and doesn't
guarantee; [compliance.md](compliance.md) maps TI requirements to code
and tests.

> ivory has had a self-review, not an external security review, and
> hasn't been tested against real TI products yet. Read
> [security.md](security.md) before you rely on it.

## Contents

1. [What you need](#1-what-you-need)
2. [Get the toolchain and the overlay](#2-get-the-toolchain-and-the-overlay)
3. [Overlay or materialized GOROOT](#3-overlay-or-materialized-goroot)
4. [Use ivory from your module](#4-use-ivory-from-your-module)
5. [TLS 1.2 for the TI](#5-tls-12-for-the-ti)
6. [TLS 1.3 with Brainpool](#6-tls-13-with-brainpool)
7. [Editors](#7-editors)
8. [CI](#8-ci)
9. [New Go releases](#9-new-go-releases)
10. [Troubleshooting](#10-troubleshooting)

## 1. What you need

- linux/amd64 (the only platform tested).
- git and bash.
- Any installed Go ≥ 1.22. It only builds the overlay tool and downloads
  the Go release that ivory pins (`overlay/GOVERSION`); everything else
  runs on that release.
- OpenSSL, for ivory's interop tests only. TLS 1.3 with Brainpool needs
  OpenSSL ≥ 3.2.

## 2. Get the toolchain and the overlay

All commands run from a checkout of ivory. `scripts/ivory-overlay` builds
the overlay tool (`cmd/ivory-overlay`) with the Go on your PATH and runs
it; `scripts/ivory-overlay <command> -h` lists a command's flags.

```sh
# Download the pinned Go release into ~/.cache/ivory/<version>, from the Go
# module proxy, verified by the checksum database.
scripts/ivory-overlay toolchain

# Check the pristine files against overlay/pins and build the overlay of a
# profile.
scripts/ivory-overlay build -profile core

# Check the result: versions, pins, builds, and a program that uses the
# patched API.
scripts/ivory-overlay doctor -profile core
```

Profiles:

| Profile | Patches | For |
|---|---|---|
| `core` | P0–P5, the patches meant for the Go project | every program |
| `kt` | `core` plus P6 and P7 | eHealth card terminals (KT) only |

Everything the tool writes goes to `$IVORY_CACHE` (default
`~/.cache/ivory`); it never writes into your module. It refuses to
replace a non-empty output directory that it didn't create.

## 3. Overlay or materialized GOROOT

There are two ways to use the patched standard library. Both build the
same program.

**Overlay (`GOFLAGS`).** The go command replaces the patched files at
build time:

```sh
eval "$(scripts/ivory-overlay env -profile core)"
# GOROOT and PATH: the pinned release; GOTOOLCHAIN=local;
# GOFLAGS="-overlay=…/overlay.json -tags=ivory,ivory_core"
go build ./...
```

**Materialized GOROOT.** A full copy of the pinned release with the
patches applied. It needs no `-overlay` flag, only the build tags:

```sh
scripts/ivory-overlay materialize -profile core
eval "$(scripts/ivory-overlay env -profile core -materialized)"
# GOROOT and PATH: ~/.cache/ivory/goroot/<version>-core;
# GOFLAGS="-tags=ivory,ivory_core"
go build ./...
```

| | Overlay | Materialized GOROOT |
|---|---|---|
| Disk | the patched files only (22 for `core`, 29 for `kt`) | a full Go installation (about 250 MB) |
| Needs `-overlay` in every go command | yes (`GOFLAGS` does it) | no |
| gopls and other tools that read source themselves | **no**: they see the pristine files (Section 7) | yes |
| Docker images, BoGo | possible | simpler |

Rules for both:

- Always run with `GOTOOLCHAIN=local` (`env` sets it). A Go downloaded by
  `GOTOOLCHAIN` lives in the module cache, which overlays can't patch.
- Rebuild after changing ivory or its patches. `doctor` reports a stale
  build.
- Settings that the patches add to `GODEBUG` (`x509unknowncurve`) work
  only through the `GODEBUG` environment variable. A `//go:debug` line
  for them fails with "unknown //go:debug setting", because the go command
  itself is not rebuilt.

## 4. Use ivory from your module

The overlay patches the toolchain, not a module, so it works for any
module. Your module needs:

- `go 1.27` (or the series of the pinned release) in `go.mod`, and a
  requirement on `github.com/DominicBreuker/ivory`. Use the same ivory
  version for the module and for the overlay checkout: the packages use
  the API of the patches of their own version.
- The build constraint `//go:build ivory` in files that use API added by
  the patches (`tls.Config.KeyExchanges`, `SignatureSchemes`,
  `VerifyUnsupportedSignature`, …) or the packages `tlsutil` and `ti`.
  Without the overlay, the build then fails with a clear error instead of
  a confusing one:

  ```
  $ GOFLAGS=-tags=ivory go build .       # tag, but no overlay
  tlsutil/tlsutil.go:50:52: undefined: tls.KeyExchange
  $ GOFLAGS= go build .                  # neither
  package example.com/tiserver: build constraints exclude all Go files in …
  ```

Packages:

| Package | What | Needs the overlay |
|---|---|---|
| `brainpool` | brainpoolP256r1, P384r1, P512r1: ECDSA, ECDH, key generation; constant time | no |
| `x509util` | parse Brainpool keys; check certificate, CSR and CRL signatures by Brainpool keys | no (Brainpool certificates themselves parse only with the overlay, P1) |
| `tlsutil` | Brainpool groups, signature verification and signers for `crypto/tls` | yes |
| `ti` | `tls.Config` presets and certificate checks for TI roles | yes (except `Verifier` and the session helpers) |

## 5. TLS 1.2 for the TI

The `ti` presets set everything the TI asks of a TLS 1.2 connection:
TLS 1.2 only, the role's cipher suites, the groups P-256, P-384,
brainpoolP256r1 and brainpoolP384r1, Brainpool signature verification,
and a certificate check in `VerifyConnection`.

```go
//go:build ivory

package main

import (
	"crypto/tls"
	"crypto/x509"

	"github.com/DominicBreuker/ivory/ti"
	"github.com/DominicBreuker/ivory/tlsutil"
)

func configs(ca *x509.Certificate) (server, client *tls.Config, err error) {
	// A Brainpool identity: PKCS #8 or SEC 1 key, PEM. For a key on a smart
	// card, use tlsutil.Certificate with tlsutil.RawSigner.
	cert, err := tlsutil.LoadX509KeyPair("server.pem", "server.key")
	if err != nil {
		return nil, nil, err
	}
	server = ti.ServerConfig([]tls.Certificate{cert}, nil) // nil: no client certificate

	// The client checks the server certificate against stored CA
	// certificates (two levels, no path building), as TI products do.
	client = ti.ClientConfig(nil, &ti.Verifier{CAs: []*x509.Certificate{ca}})
	client.ServerName = "localhost"
	return server, client, nil
}
```

- `x509.ParseCertificate` parses Brainpool certificates with the overlay
  (P1): `PublicKeyAlgorithm` is `UnknownPublicKeyAlgorithm` and
  `PublicKey` is nil. `crypto/x509` can't verify their signatures, so
  `x509.Certificate.Verify` never accepts a chain with a Brainpool key.
  The presets set `InsecureSkipVerify` and verify in `VerifyConnection`
  with `x509util`. If you write your own configuration, do the same:
  `InsecureSkipVerify` without a `VerifyConnection` check accepts any
  certificate.
- Other presets: `ti.KTServer` (card terminal with an RSA and a Brainpool
  identity, `RequestClientCert`, the connection states of the SICCT
  channel), `ti.ConnectorClientConfig` and `ti.KonnektorVerifier`
  (Konnektor towards a terminal), `ti.AddBrainpoolP512r1` (where
  brainpoolP512r1 is allowed). See the package documentation and
  `examples/ktserver`, `examples/connectorclient`.
- Session resumption: server presets disable session tickets.
  `ti.SessionTickets` enables them with key rotation and a 24 h limit,
  `ti.NewClientSessionCache` is a client cache with the same limit
  (GS-A_5322).

## 6. TLS 1.3 with Brainpool

TLS 1.3 uses other IDs for the Brainpool groups (31–33) and signature
schemes bound to the curve (0x081A–0x081C, RFC 8734). The TI presets stay
on TLS 1.2 (see [security.md](security.md)); for TLS 1.3, configure
`crypto/tls` directly:

```go
verifier := &tlsutil.ChainVerifier{
	Roots:    []*x509.Certificate{ca},
	KeyUsage: x509.ExtKeyUsageServerAuth, // also checks ServerName
}
server := &tls.Config{
	MinVersion:                 tls.VersionTLS13,
	Certificates:               []tls.Certificate{cert}, // from tlsutil.LoadX509KeyPair
	KeyExchanges:               tlsutil.KeyExchanges(brainpool.P256r1()),
	SignatureSchemes:           tlsutil.SignatureSchemes(),
	VerifyUnsupportedSignature: tlsutil.VerifyUnsupportedSignature,
}
client := &tls.Config{
	MinVersion:                 tls.VersionTLS13,
	ServerName:                 "localhost",
	KeyExchanges:               tlsutil.KeyExchanges(brainpool.P256r1()),
	CurvePreferences:           []tls.CurveID{tlsutil.CurveBrainpoolP256r1TLS13},
	SignatureSchemes:           tlsutil.SignatureSchemes(),
	VerifyUnsupportedSignature: tlsutil.VerifyUnsupportedSignature,
	InsecureSkipVerify:         true, // verified by VerifyConnection below
	VerifyConnection:           verifier.VerifyConnection,
}
```

What each setting does:

- **`SignatureSchemes`** must contain 0x081A–0x081C
  (`tlsutil.SignatureSchemes()` does), **and `VerifyUnsupportedSignature`
  must be set**. Otherwise the Brainpool schemes are never advertised, and
  the peer can't present a Brainpool certificate.
- **`KeyExchanges`** adds the Brainpool groups: 26–28 for TLS 1.2 and
  31–33 for TLS 1.3.
- **`CurvePreferences`** decides the client's key share. Go's built-in
  groups always come before external ones, and a TLS 1.3 client sends a
  key share only for its first group. To send a Brainpool key share in
  the first ClientHello, list only Brainpool groups; otherwise a server
  that wants Brainpool answers with a HelloRetryRequest (one more round
  trip, still correct).
- A Go client always offers ChaCha20-Poly1305 in TLS 1.3, whatever
  `CipherSuites` says. That's why the TI presets don't enable TLS 1.3.
- OpenSSL supports the Brainpool groups and schemes in TLS 1.3 from
  version 3.2 on; 3.0 only in TLS 1.2. BouncyCastle's JSSE provider for
  Java supports them in TLS 1.2 and TLS 1.3 (tested with 1.86; the group
  names there are `brainpoolP256r1tls13` and so on, set with the system
  property `jdk.tls.namedGroups`).

## 7. Editors

Use a **materialized GOROOT** for editors. gopls doesn't apply a
`GOFLAGS` overlay: it reads the source files itself, so it sees the
pristine standard library. With gopls v0.23.0 on a module that uses
`tls.Config.KeyExchanges`:

| Environment | `gopls check main.go` |
|---|---|
| pinned release, `GOFLAGS=-tags=ivory` | `unknown field KeyExchanges in struct literal of type tls.Config` |
| `env -profile core` (overlay in `GOFLAGS`) | the same errors, although `go build` succeeds |
| `env -profile core -materialized` | no diagnostics |

Set up an editor like this:

1. `scripts/ivory-overlay materialize -profile core`
2. Point the editor's Go installation (GOROOT) at
   `~/.cache/ivory/goroot/<version>-core`, and add the build tags
   `ivory,ivory_core`.
3. Install gopls with that Go, or any recent one.

VS Code (`settings.json`; these settings were not tested here, only the
gopls command line above):

```json
{
  "go.goroot": "/home/you/.cache/ivory/goroot/go1.27.2-core",
  "go.toolsEnvVars": { "GOFLAGS": "-tags=ivory,ivory_core", "GOTOOLCHAIN": "local" },
  "gopls": { "build.buildFlags": ["-tags=ivory,ivory_core"] }
}
```

Other editors: set GOROOT and the build tags the same way, or start the
editor from a shell after `eval "$(scripts/ivory-overlay env -profile
core -materialized)"`.

## 8. CI

The same commands work in CI; ivory's own CI runs them. A GitHub Actions
job for your module (replace `vX.Y.Z` by the ivory version in your
`go.mod`):

```yaml
jobs:
  test:
    runs-on: ubuntu-24.04
    env:
      IVORY_VERSION: vX.Y.Z
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-go@v5
        with:
          go-version: '1.24.x'   # any Go >= 1.22: it only bootstraps the pinned release
          cache: false
      - name: ivory toolchain and overlay
        run: |
          git clone --depth=1 --branch "$IVORY_VERSION" https://github.com/DominicBreuker/ivory "$RUNNER_TEMP/ivory"
          "$RUNNER_TEMP/ivory/scripts/ivory-overlay" toolchain
          "$RUNNER_TEMP/ivory/scripts/ivory-overlay" build -profile core
      - name: vet and test
        run: |
          eval "$("$RUNNER_TEMP/ivory/scripts/ivory-overlay" env -profile core)"
          go vet ./...
          go test ./...
```

- Every step that runs the go command needs the `eval` line, or put the
  materialized GOROOT's `bin` on `$GITHUB_PATH` and set `GOFLAGS` in the
  job's `env`.
- Cache `~/.cache/ivory/<version>` (the toolchain, about 250 MB) with
  `actions/cache`, keyed by the version in `overlay/GOVERSION`.

## 9. New Go releases

ivory pins one Go release; README.md lists it. When Go publishes a patch
release, ivory adopts it with one command, run in a clean checkout of
ivory:

```sh
scripts/ivory-overlay latest   # pinned release, its newest patch release, newest release
scripts/ivory-overlay adopt    # or: adopt -go go1.27.3
```

`adopt` downloads the release, reports which patched files changed,
applies every patch, rebases those whose hunks moved, writes the new pins
and `overlay/GOVERSION`, updates the README, and runs the test suite for
every profile (Go's `crypto/x509` and `crypto/tls` tests, ivory's tests
with and without the overlay, full BoGo). It commits nothing. A patch
whose context changed fails with the rejected hunks; it needs a rebase
by hand. Going from go1.27.1 to go1.27.2 took 3 minutes 16 seconds,
download included.

## 10. Troubleshooting

| Symptom | Cause and fix |
|---|---|
| `unknown field KeyExchanges in struct literal` or `undefined: tls.KeyExchange` | no overlay: `eval "$(scripts/ivory-overlay env …)"`, or a materialized GOROOT. In an editor, see Section 7. |
| `build constraints exclude all Go files` | the `ivory` build tag is missing from `GOFLAGS` |
| `go: downloading go1.27.x` | `GOTOOLCHAIN` is not `local`; the downloaded Go can't be patched |
| `… does not match its pin` | the toolchain in `~/.cache/ivory` was changed; delete it and run `toolchain` again |
| `no pins for goX.Y.Z` | that release is not supported; use the release in `overlay/GOVERSION`, or `adopt` |
| `x509: unsupported elliptic curve` | the program was built without the overlay, or runs with `GODEBUG=x509unknowncurve=0` |
| `tls: … certificate contains an unsupported type of public key: <nil>` | the peer has a Brainpool certificate and `VerifyUnsupportedSignature` is not set |
| TLS 1.3 peer sends no Brainpool certificate | `SignatureSchemes` lacks 0x081A–0x081C, or `VerifyUnsupportedSignature` is not set (Section 6) |
| OpenSSL: "wrong curve" in TLS 1.2 | OpenSSL refuses an ECDSA certificate on a curve the peer didn't list in `supported_groups`; offer the Brainpool groups (`KeyExchanges`, or OpenSSL's `-groups`) |
| `tlsutil: certificate … doesn't allow extended key usage anyExtendedKeyUsage` | set `ChainVerifier.KeyUsage` (for example `x509.ExtKeyUsageServerAuth`) |

`scripts/ivory-overlay doctor -profile <p>` prints the versions, the pin
check and the builds, and runs a program that parses a Brainpool
certificate and uses the patched API.
