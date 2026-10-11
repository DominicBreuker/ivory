# The ivory overlay

Patches to Go's `crypto/tls` and `crypto/x509`, applied to a pinned Go
release. One patch per concern. Each upstream patch is written as a future
Go change (CL): Go style, tests in the style of the Go tree that need no
Brainpool math, and the API names of the upstream design.

## Patches

| # | File | Concern | Requirement | Profiles | Upstream | Status |
|---|---|---|---|---|---|---|
| P0 | `patches/0000-crypto-tls-no-renegotiation.patch` | a TLS 1.2 server refuses a client-initiated renegotiation with a fatal `no_renegotiation` alert instead of a fatal `unexpected_message` | GS-A_5524 (gemSpec_KT V3.17.1) | core, kt | bug fix; not filed yet | done |
| P1 | `patches/0100-crypto-x509-unknown-named-curves.patch` | parse keys on unsupported named curves as `UnknownPublicKeyAlgorithm`; `Verify` results unchanged | all certificate handling | core, kt | proposal A | done |
| P2 | `patches/0200-crypto-tls-unsupported-peer-keys.patch` | `Config.VerifyUnsupportedSignature`: verify peer signatures by keys crypto/tls doesn't support | A_17124-03, A_22455, A_22890 | core, kt | proposal B | done (TLS 1.2 and 1.3) |
| P3 | `patches/0300-crypto-tls-opaque-signer-keys.patch` | sign with opaque public-key types (`Certificate.SupportedSignatureAlgorithms` required) | A_17089-03, A_22453 | core, kt | proposal B | done (TLS 1.2 and 1.3) |
| P4 | `patches/0400-crypto-tls-external-key-exchanges.patch` | `Config.KeyExchanges`: external key-exchange groups | GS-A_4384-03, A_17094-02, A_23912, A_23913 | core, kt | proposal C | done (TLS 1.2 and 1.3) |
| P5 | `patches/0500-crypto-tls-signature-schemes.patch` | `Config.SignatureSchemes`: the advertised signature schemes, including ones crypto/tls doesn't implement (TLS 1.3) | A_18467 | core, kt | via golang/go#63527 | done, provisional API |
| P6 | `patches/0900-crypto-tls-kt-certificate-types.patch` | one CertificateRequest certificate type per suite | A_22454 | kt | never | done |
| P7 | `patches/0910-crypto-tls-ecdsa-first-order.patch` | a client with `Config.CipherSuites` offers ECDSA suites before RSA suites | A_17124-03 item 3, A_17094-02 | kt | never | done |

Patch numbers follow the order in which the changes would land in Go;
gaps leave room for later patches. Each patch applies after the ones
before it and keeps `go test -short crypto/x509 crypto/tls` green.

**Upstream.** P0–P5 are written to be proposed to the Go project, in this
order: P0 as a bug fix; proposal A (P1, parse keys on unsupported named
curves); proposal B (P2 and P3, peer signatures by unsupported keys and
signing with opaque keys); proposal C (P4, external key-exchange groups);
P5 follows golang/go#63527. Nothing has been filed yet. When Go accepts a
change, ivory drops the patch for the Go releases that contain it, and
code written against the overlay keeps compiling, because the patches use
the API names of their proposals. P6 and P7 implement requirements
specific to eHealth card terminals and stay in the overlay.

### P0: no_renegotiation

- **Change** (`src/crypto/tls/conn.go`):
  - `handleRenegotiation`: a server that receives a ClientHello after the
    handshake sends `no_renegotiation`. Before, the HelloRequest type
    check came first and answered with `unexpected_message`, so the
    existing server branch was unreachable.
  - `sendAlertLocked`: `no_renegotiation` stays a warning when a client
    refuses a HelloRequest; from a server it is fatal.
- **Why fatal:** RFC 5246 §7.2.2 says `no_renegotiation` "is always a
  warning", but BoringSSL sends it as fatal and BoGo expects "remote
  error: no renegotiation". A warning-level variant passed OpenSSL but
  failed BoGo. GS-A_5524 doesn't fix the level. The level is a question
  for the Go reviewers.
- **Tests:** `TestServerRejectsRenegotiation` in
  `handshake_server_test.go` (fails on stock Go, passes with the patch);
  BoGo's `Renegotiate-Server-Forbidden` is re-enabled in
  `bogo_config.json`.

### P1: keys on unsupported named curves

- **Change** (`src/crypto/x509`):
  - `parsePublicKey` returns an unexported sentinel for a well-formed
    `id-ecPublicKey` whose named curve crypto/x509 doesn't implement
    (for example brainpoolP256r1, secp256k1, SM2, P-192).
  - `ParseCertificate` and `ParseCertificateRequest` map it to
    `PublicKeyAlgorithm = UnknownPublicKeyAlgorithm`, `PublicKey = nil`,
    and keep every other field; certificates get an unexported flag.
  - `Verify` rejects a leaf with that flag (`CertificateInvalidError`,
    `NoValidChains`) before any platform verifier, drops chains from
    the platform verifiers (Windows, macOS, iOS) that contain a flagged
    certificate (`dropUnsupportedCurveChains`), and chain building
    already skips issuers with a nil key. So `Verify` results don't
    change.
  - Malformed parameters, `implicitCurve`, `specifiedCurve` and
    `ParsePKIXPublicKey` keep failing.
  - GODEBUG `x509unknowncurve=0` restores the parse error and counts in
    `/godebug/non-default-behavior/x509unknowncurve:events`. The patch
    adds the setting to `src/internal/godebugs/table.go` and regenerates
    `src/runtime/metrics/doc.go`. Only the `GODEBUG` environment
    variable works: `cmd/go` is not rebuilt, so it rejects a
    `//go:debug x509unknowncurve=0` line ("unknown //go:debug setting",
    checked with go1.27.1).
- **Tests:** `unknown_curve_test.go`: real SPKIs from OpenSSL for six
  curves spliced into certificates and CSRs, a self-signed
  brainpoolP256r1 certificate and a CSR from OpenSSL, malformed
  parameters, bundles and `CertPool`, `Verify` with an unsupported leaf,
  intermediate and root, the platform-chain filter (runs on every
  platform), and the GODEBUG with its counter. They fail without the
  change. CI vets `crypto/x509` for windows and darwin.

### P2: `Config.VerifyUnsupportedSignature`

- **API:** `VerifyUnsupportedSignature func(leaf *x509.Certificate,
  scheme SignatureScheme, signed, sig []byte) error`.
- **Change** (`src/crypto/tls`): in TLS 1.2 and TLS 1.3, a peer leaf
  with a nil `PublicKey` is accepted if the hook is set; its
  ServerKeyExchange or CertificateVerify signature goes to the hook, after
  the usual checks that the scheme was advertised and, for a
  ServerKeyExchange, fits the cipher suite. In TLS 1.3 the scheme must be
  one crypto/tls doesn't implement (those it implements are bound to key
  types it supports), and the hook gets the TLS 1.3 signed content
  (RFC 8446, Section 4.4.3). Such schemes are advertised only through P5.
  Unset, before TLS 1.2, or in FIPS 140-3 mode: today's
  `unsupported_certificate` alert. `Config.Clone` copies the field.
- **Alerts** (unchanged from supported keys): a client sends
  `illegal_parameter` for any bad ServerKeyExchange (scheme not
  advertised, scheme not matching the suite, bad signature); a server
  sends `illegal_parameter` for a CertificateVerify scheme it didn't
  advertise and `decrypt_error` for a bad CertificateVerify signature.
  Whether the scheme fits the key is the hook's check. In TLS 1.3, an
  implemented scheme from such a key draws `illegal_parameter`.
- **Tests:** `unsupported_key_test.go` builds a certificate whose key
  names a made-up curve OID but holds a P-256 point, and verifies with
  crypto/ecdsa: hook unset, set, failing, TLS 1.3 with an implemented
  scheme, both roles, an empty client certificate, FIPS mode. A connection wrapper rewrites the
  peer's ServerKeyExchange or CertificateVerify scheme: not advertised,
  RSA or RSA-PSS scheme on an ECDSA suite, ECDSA scheme on an RSA suite,
  RSA scheme from an EC client key. Removing the scheme checks makes
  them fail. `TestCloneFuncFields` lists the field.

### P3: opaque signer keys

- **API:** none; a documented rule on
  `Certificate.SupportedSignatureAlgorithms`.
- **Change** (`src/crypto/tls`): for a `crypto.Signer` whose public key
  type crypto/tls doesn't implement, `SupportedSignatureAlgorithms` is
  required and authoritative. Never in FIPS 140-3 mode.
  - **TLS 1.2:** the listed schemes crypto/tls implements are used; they
    must be all ECDSA or all RSA (PKCS #1 v1.5 or RSA-PSS). That type sets
    `ecSignOk`/`rsaSignOk` in `processClientHello` and the suite check in
    `ClientHelloInfo.SupportsCertificate`, which skips the curve check
    against `supported_groups`. Signing goes through `crypto.SignMessage`
    as for other keys.
  - **TLS 1.3:** only the listed schemes crypto/tls doesn't implement are
    used (such as 0x081A–0x081C, RFC 8734), because the ones it implements
    are bound to key types it implements: 0x0403 means "ECDSA with
    SHA-256" in TLS 1.2 but "P-256" in TLS 1.3. The key must be a
    `crypto.MessageSigner`; `SignMessage` gets the unhashed content and a
    new `*SignatureSchemeOptions{Scheme}` (`HashFunc` returns 0). A
    dedicated type, rather than making `SignatureScheme` a
    `crypto.SignerOpts`, keeps `rsaKey.Sign(rand, digest,
    PSSWithSHA256)` from compiling into a silent PKCS #1 v1.5 signature.
- **Tests:** `opaque_key_test.go` wraps a P-256 key in a signer whose
  `Public()` returns an unknown type: server and client signing (and the
  hash passed to `Sign`), selection between an RSA and an opaque ECDSA
  certificate by the client's suites, both `SupportsCertificate`
  methods with acceptable CAs, missing or mixed schemes, FIPS mode. In
  TLS 1.3, both roles sign with a private-use scheme (0xFE01, P-256 with
  SHA-256 in the tests) that the peer verifies with P2's hook; errors for
  a signer without `SignMessage`, only implemented schemes, and a scheme
  the peer didn't advertise. They fail without the change.

### P4: `Config.KeyExchanges`

- **API:** `type KeyExchange struct { ID CurveID; MinVersion,
  MaxVersion uint16; GenerateKey func() (crypto.Decapsulator, error);
  NewEncapsulator func([]byte) (crypto.Encapsulator, error) }` and
  `Config.KeyExchanges []KeyExchange`.
- **Change** (`src/crypto/tls`): external groups come after the built-in
  ones in `supported_groups`, filtered by `CurvePreferences`; the TLS 1.2
  ECDHE key agreement and the TLS 1.3 key shares use the KEM for them
  (in TLS 1.3 the client generates and the server encapsulates, as for
  ML-KEM); one fresh key per handshake; an entry with a built-in ID, or
  two entries with the same ID for overlapping versions, are an error;
  never in FIPS 140-3 mode.
  - A TLS 1.3 client sends a key share for its first group, an external
    one if `CurvePreferences` lists only external groups; a server may
    select an external group in a HelloRetryRequest.
  - A client that also offers TLS 1.2 lists the TLS 1.2-only groups after
    the others, and doesn't offer TLS 1.3 if it has no group for it (in
    `Config.supportedVersions`, so that the downgrade check agrees).
  - An HRR selecting a group the client offered only for TLS 1.2 draws
    `illegal_parameter`.
- **Tests:** `key_exchange_test.go` with `crypto/ecdh` wrapped as KEMs
  under private-use IDs 0xFE01 and 0xFE02: TLS 1.2 and TLS 1.3, order and
  filtering, version scoping, key shares, HelloRetryRequest (also for a
  TLS 1.2-only group), invalid shares in both versions, built-in IDs,
  duplicate IDs, FIPS mode. `TestCloneNonFuncFields` lists the field.

### P5: `Config.SignatureSchemes` (provisional)

- **API:** `SignatureSchemes []SignatureScheme`, shaped like the field
  requested in golang/go#63527, marked provisional in its doc comment.
- **Change** (`src/crypto/tls`): if set, it replaces the default list in
  `signature_algorithms` (ClientHello and CertificateRequest) and
  `signature_algorithms_cert`, in preference order, and the peer's
  handshake signatures must use one of its values. Values disabled for
  the versions offered, in FIPS 140-3 mode or by GODEBUG settings are
  dropped from `signature_algorithms`, as from the default list.
  Values crypto/tls doesn't implement are advertised only for TLS 1.3 and
  only if `VerifyUnsupportedSignature` is set (and not in FIPS mode). It
  doesn't restrict local signing. `Config.Clone` copies it.
- **Upstream:** if #63527 adds such a list, P5 shrinks to "values this
  package doesn't implement are allowed when `VerifyUnsupportedSignature`
  is set".
- **Tests:** `signature_schemes_test.go`: the advertised lists (default,
  with and without the hook, TLS 1.2 only, SHA-1, the `_cert` list),
  certificates refused for unlisted schemes in both roles, a TLS 1.3
  handshake with an unsupported key and a private-use scheme in both
  roles without test hooks, FIPS mode; `TestCloneNonFuncFields`.

### P6: one CertificateRequest certificate type (kt)

- **Change** (`handshake_server.go`, `doFullHandshake`): a TLS 1.2 server
  sends `certificate_types = [ecdsa_sign]` on ECDHE_ECDSA suites and
  `[rsa_sign]` on RSA suites, instead of both. A Go client then sends the
  certificate that matches the suite. `supported_signature_algorithms`
  lists only the algorithms of that type: ECDSA and Ed25519 (RFC 8422,
  Section 5.5) with `ecdsa_sign`, RSA-PSS and PKCS #1 v1.5 with
  `rsa_sign`. RFC 5246 doesn't require the two lists to agree, but strict
  clients (tlslite-ng, so tlsfuzzer) reject a CertificateRequest whose
  algorithms need a type it doesn't list. A client that ignores
  `certificate_types` can't sign with the other key type either: the
  server refuses a CertificateVerify whose algorithm it didn't offer.
- **Tests:** `certificate_types_test.go` records the CertificateRequest
  on both suites, checks both lists and which of two client certificates
  is sent; it fails without the change. The TLS 1.2 `TestClientAuth`
  recordings were regenerated with OpenSSL 1.1.1w (`handshake_test.go`
  asks for 1.1.1); its RSA client certificate cases and
  `TestPKCS1OnlyCert` now use a server with an RSA certificate. P2's
  `TestVerifyUnsupportedSignatureCertificateVerifyScheme` names Ed25519
  instead of an RSA scheme as the advertised scheme of another key type,
  since the server offers no RSA scheme on its ECDSA suite (the patch
  changes a file that P2 adds; `ivory-overlay pin` pins only files of the
  pristine release). Tests read testdata from disk, not through the
  overlay, so `stdtest` tests the kt profile in a materialized GOROOT.
  Full BoGo passes with five tests disabled in `bogo_config.json`
  (`TLS12-Server-ClientAuth-ECDSA`, `Server-Verify-*-TLS12` for ECDSA
  and Ed25519): their client signs with an ECDSA or Ed25519 key towards
  a server with an RSA certificate, which the narrowed list rules out.
- **Probe:** K3 (`40` on ECDHE_ECDSA, `01` on ECDHE_RSA). Interop: I10
  (both lists, seen by OpenSSL), F6 (tlsfuzzer's consistency check).

### P7: ECDSA suites first (kt)

- **Change** (`common.go`, `Config.cipherSuites`): if
  `Config.CipherSuites` is set, a client offers its ECDHE_ECDSA suites
  before its ECDHE_RSA suites of the same kind (AEAD, CBC, …); Go's order
  is kept otherwise. Without `Config.CipherSuites` nothing changes, which
  keeps the recorded handshake tests valid (changing Go's preference
  lists instead re-recorded 52 testdata files, a 695 KB patch). Servers
  are unchanged: they choose the certificate first, and the suite must
  match its key.
- **Tests:** `ecdsa_first_test.go`: `cipherSuites` with and without AES
  hardware, and the ClientHello as a server sees it; it fails without the
  change.
- **Probe:** K1 (C02B, C02C, C02F, C030 for the TI suites).

## Layout

| Path | Contents |
|---|---|
| `GOVERSION` | the pinned Go release, for example `go1.27.2` |
| `patches/` | one patch per concern, paths `src/...` relative to GOROOT, against the pinned release |
| `profiles/<name>.txt` | the patches of a profile, in order |
| `pins/<version>.sha256` | SHA-256 of every pristine file the patches touch |
| `tip-rewrites.txt` | rewrites that adapt the patched files to Go's development branch (`tipcheck`) |

## Building

The overlay tool is `cmd/ivory-overlay` (a module of its own, so that any
Go ≥ 1.22 builds it); `scripts/ivory-overlay` builds and runs it.

`scripts/ivory-overlay stdtest -profile <name>` runs `go test -short
crypto/x509 crypto/tls` under the overlay. Tests read `testdata/` from
disk, not through the overlay, so for a profile whose patches change
testdata (kt: P6) it tests a materialized GOROOT instead.

`scripts/ivory-overlay build -profile <name>`:

1. checks the pristine files that the profile's patches touch against
   `pins/<version>.sha256`;
2. copies them to `$IVORY_CACHE/overlay/<version>-<profile>/src/...`;
3. applies the patches in order with `git apply` (no fuzz);
4. writes `overlay.json` with absolute paths, and an `IVORY-STAMP` with
   the Go version, profile and patch hashes.

`scripts/ivory-overlay materialize` applies the same patches to a full
copy of GOROOT instead.

`scripts/ivory-overlay tipcheck -profile core` applies the patches to the
tip of Go's development branch and reports, per patch, whether it applies
as is, with moved hunks, or not. Then it applies the literal rewrites in
`tip-rewrites.txt` to the files the patches write: they follow changes on
the development branch that the pinned release doesn't have yet (for
example, crypto/tls test helpers that became functions), and the
patches' upstream versions need them too. `-test` also builds that tree
and runs `go test -short` and `go vet` on `crypto/x509` and `crypto/tls`
in it.

## New Go releases

`scripts/ivory-overlay adopt` (or `adopt -go <version>`) moves to a new
release: it downloads it, lists the patched files that changed, applies
the patches in a scratch git repository and exports again those whose
hunks moved (`git diff` without `index` lines, as the patches are made),
sets their `Base:` notes, writes the new pins and `GOVERSION`, removes the
old pins, updates the README table, and runs build, `stdtest`, the
module's vet and tests (with and without the overlay) and full BoGo for
every profile. A patch whose context changed stops it with the rejected
hunks; rebase that one by hand (below). It commits nothing.

## How the overlay works (facts and limits)

- **Format.** `-overlay=file.json` takes `{"Replace": {"<original>":
  "<replacement>"}}` with absolute paths. A path that doesn't exist adds a
  file; an empty replacement deletes one. It applies to the go command's
  view of all source, GOROOT included, for `build`, `test`, `vet` and
  `list`.
- **Whole files.** Each entry is a full copy of a patched file, so the
  overlay must be rebuilt for every Go release, and the pristine files are
  checked by hash first.
- **Not inside GOMODCACHE.** The overlay can't replace files under
  `GOMODCACHE`. The toolchain must be a normal directory, not one that
  `GOTOOLCHAIN` downloaded automatically; `ivory-overlay toolchain` copies
  it out of the module cache. Always run with `GOTOOLCHAIN=local`.
- **GOFLAGS.** `GOFLAGS="-overlay=/abs/overlay.json -tags=ivory"`. The go
  command applies a GOFLAGS flag only to subcommands that know it.
- **GODEBUG settings added by a patch** work only through the `GODEBUG`
  environment variable, because the overlay doesn't rebuild `cmd/go`. Such
  a patch must also replace `src/internal/godebugs/table.go`.
- **Go's own tests run under the overlay,** including test files that a
  patch adds.
- **BoGo** reads `bogo_config.json` from disk, not through the overlay, so
  `ivory-overlay bogo` runs it in a materialized GOROOT. BoringSSL comes
  through the module proxy.
- **Cross-compiling works**: the overlay is source-level.
- **Editors:** gopls doesn't apply a GOFLAGS overlay: it reads the source
  files itself and reports the patched API as missing (gopls v0.23.0,
  `unknown field KeyExchanges`). With a materialized GOROOT and the build
  tags it reports nothing. Use a materialized GOROOT for editors.

## Adding or changing a patch

1. Materialize a scratch GOROOT, or copy the pristine files, and edit
   there. Never edit the files under `$IVORY_CACHE` by hand.
2. Write the test first, in the Go tree's style, and check that it fails
   without the change.
3. Export the patch with `--- a/src/...` and `+++ b/src/...` headers and
   put a commit-message-style description above the first `---` line.
4. Add it to the profiles, run `scripts/ivory-overlay pin`, then `build`
   and `stdtest` for every profile, and `bogo` for TLS changes.
5. A patch that adds a `tls.Config` field also updates
   `TestCloneNonFuncFields` or `TestCloneFuncFields`.
6. Hooks are off in FIPS 140-3 mode, and Go's builders run the crypto
   tests in that mode too: a test that needs a hook starts with
   `skipFIPS(t)`, and one test per patch checks the FIPS behavior. Run
   `GOFIPS140=latest scripts/ivory-overlay stdtest` as well (CI does).
7. A patch that changes what crypto/tls writes may break recorded
   handshake tests (`testdata/Client-*`, `Server-*`). Re-record them with
   `go test crypto/tls -run <Test> -args -update`, with OpenSSL 1.1.1 first
   on PATH (`handshake_test.go` refuses other versions), and keep the
   changed testdata in the patch.

## License

The patches modify Go source files. Those files, and the patched copies
the tools produce, stay under Go's BSD-3-Clause license, Copyright The Go
Authors.
