# ivory security notes

What ivory guarantees, what it relies on, and what it leaves to the
product that uses it; Section 8 covers the `ivory` test tool. The [user guide](user-guide.md) shows how to use it;
[compliance.md](compliance.md) maps TI requirements to code and tests.

> **Status:** ivory has had a self-review, not an external one. Get an
> external review of the Brainpool code and the patches before production
> use.

## 1. The patches

The overlay patches `crypto/x509` and `crypto/tls` of a pinned Go release.
They contain no cryptography of their own: they let code outside the
standard library take part where Go rejects keys and groups it doesn't
implement.

- **Opt-in.** Without the new `tls.Config` fields, a patched `crypto/tls`
  behaves like Go's. The one exception is P0: a TLS 1.2 server refuses
  renegotiation with a `no_renegotiation` alert instead of
  `unexpected_message`; it refused before too.
- **Fail closed.** A peer key that `crypto/tls` doesn't support is
  rejected unless `Config.VerifyUnsupportedSignature` is set, and its
  error rejects the handshake. The usual checks still run first: the
  signature scheme must be one that was advertised, and in TLS 1.2 it must
  fit the cipher suite.
- **Off in FIPS 140-3 mode.** With `GODEBUG=fips140=on`, the hooks
  (`VerifyUnsupportedSignature`, `KeyExchanges`, signing with opaque key
  types, unknown `SignatureSchemes`) are not used.
- **Certificate verification doesn't change.** `crypto/x509` now parses
  certificates with keys on curves it doesn't implement (P1), but
  `Certificate.Verify` never returns a chain that contains one, on any
  platform. `GODEBUG=x509unknowncurve=0` restores the old parse error.

### Your code verifies Brainpool chains

Because `crypto/x509` can't verify Brainpool signatures, TLS
configurations with Brainpool peers set `InsecureSkipVerify` and check
the peer in `VerifyConnection`:

- `ti.Verifier` checks a certificate the way TI products do: issued
  directly by one of the stored CA certificates (two levels, no path
  building; the CA is found by name, authority key identifier and
  signature), validity, keyUsage, extended key usage, policies, no
  unknown critical extensions, optional CRLs.
- `tlsutil.ChainVerifier` checks a short chain against root certificates
  (validity, CA flags, path length constraints, no unknown critical
  extensions, extended key usage, host name).

The `ti` presets wire this up. **A configuration of your own with
`InsecureSkipVerify` and no `VerifyConnection` check accepts any
certificate.**

## 2. Constant time

| Code | Handles secrets | Constant time |
|---|---|---|
| `brainpool`: key generation, ECDH, ECDSA signing, KEM | private scalars, nonces, shared secrets | yes: Montgomery ladder over all scalar bits with complete addition formulas, conditional swaps by masks, `filippo.io/bigmod` without its VarTime functions, Fermat inversion; no `math/big`. Branches only in rejection loops with secret-independent outcome. |
| `brainpool`: verification, public key parsing | no | uses the same code |
| `x509util` | no (parses public keys and certificates; private key parsing hands the scalar to `brainpool`) | not needed |
| `tlsutil` | passes keys to `brainpool` or a card | not needed |
| the patches | no | not needed |

Limits of that statement:

- It is a source and assembly review plus a statistical timing test
  (Welch's t-test on the scalar multiplication), done by the developers.
- It assumes that 64-bit multiplication and addition with carry take
  data-independent time (true for current x86-64 cores). Power and
  electromagnetic side channels are not considered.
- `filippo.io/bigmod` (the module form of Go's internal `bigmod`) is
  trusted; only how ivory calls it was reviewed.

## 3. Random numbers

- **Source.** `brainpool` takes all randomness from `crypto/rand`. In the
  pinned Go release, `crypto/rand.Reader` uses `getrandom(2)` on Linux, and
  Go's key generation and signing functions ignore a caller's
  `io.Reader` since Go 1.26 (unless `GODEBUG=cryptocustomrand=1`).
  `brainpool` does the same: its `rand` parameters are ignored.
- **Signatures** use RFC 6979 nonces hedged with fresh random bytes
  (RFC 6979, Section 3.6): two signatures of the same message differ, and
  a failing random source doesn't reveal the key.
- **Certification.** BSI TR-03116-1 (V3.20, Sections 3.8 and 3.9) requires
  a deterministic RNG of class DRG.3 (AIS 20) or a physical RNG of class
  PTG.2 (AIS 31) for key generation, and at least DRG.2 or PTG.2 for
  challenges and padding. Whether the Linux kernel's RNG on your platform
  meets that is a property of the platform, not of ivory; the product
  must provide the evidence. Long-term keys generated on a smart card
  (gSMC-KT, SMC-B, HBA) don't depend on it. Use `tlsutil.RawSigner` to
  sign with them.

## 4. Erasure of secrets

GS-A_5322 (gemSpec_Krypt V2.51.0) asks that TLS key material be "sicher
gelöscht" after at most 24 hours. Go can't guarantee that:

- The garbage collector frees memory without clearing it and may have
  copied values before (stack growth, slices).
- `crypto/tls` keeps session secrets in its own structures; no API wipes
  them.
- `runtime/secret` (`secret.Do`) erases registers, stack and, eventually,
  heap allocations of a function call, but in the pinned release it exists
  only with `GOEXPERIMENT=runtimesecret`, isn't covered by Go's
  compatibility promise, and ivory doesn't use it.

What ivory does: every handshake uses a fresh ephemeral key; the `ti`
server presets disable session tickets; `ti.SessionTickets` rotates
ticket keys (none older than 48 hours with daily rotation) and refuses
sessions older than 24 hours; `ti.NewClientSessionCache` drops a session
24 hours after the full handshake that created its secret. That bounds
how long secrets are *used*, not how long they stay in memory. A product
that must show erasure needs measures outside Go (process lifetime,
memory protection) and an argument for its evaluator.

## 5. Protocol choices

- **TLS 1.2 only in the `ti` presets.** A Go TLS 1.3 client always offers
  ChaCha20-Poly1305, which BSI TR-02102-2 doesn't allow, and gemSpec_Krypt
  allows TLS 1.3 only with TR-02102-2 configurations. TLS 1.3 with
  Brainpool works (user guide, Section 6), but not with a TI-compliant
  cipher suite offer from a Go client.
- **SHA-1** is not used in TLS 1.2 handshake signatures by default since
  Go 1.25 (`GODEBUG=tlssha1=0`). Don't re-enable it; A_21275-01 forbids it.
  `tlsutil.VerifyUnsupportedSignature` and `x509util` reject SHA-1 for
  Brainpool keys in any case.
- **Renegotiation** is refused (P0, GS-A_5524).
- **Brainpool groups** come after Go's built-in groups. A peer that
  supports both negotiates P-256 or P-384 in TLS 1.2 with the `ti`
  presets; Brainpool is used when the peer offers only Brainpool.
- **Session resumption** (`ti`): see Section 4.
- **`tlsutil.TLS12Fallback`** (opt-in) lets a server for TLS 1.2 and
  1.3 answer in TLS 1.2 a client whose TLS 1.3 can't use the server's
  Brainpool identity (Windows SChannel, OpenSSL before 3.2). It decides
  from the ClientHello alone and only where TLS 1.3 would fail anyway,
  so an RFC 8734 client keeps TLS 1.3. The connection then is TLS 1.2
  with the config's TLS 1.2 settings; no TLS 1.3 downgrade sentinel is
  sent, since the server offers TLS 1.2 only for that connection. An
  active attacker who edits a client's ClientHello to trigger it breaks
  the TLS 1.2 Finished check and gets a failed handshake, not a
  downgrade. ivory never signs or verifies TLS 1.3 handshakes with
  Brainpool keys under other schemes than 0x081A–0x081C.

## 6. The toolchain

- `ivory-overlay toolchain` downloads the pinned release from the Go
  module proxy; the go command checks it against the Go checksum
  database.
- Every build checks the files the patches touch against SHA-256 pins in
  `overlay/pins` before it applies them, and refuses a mismatch.
- The overlay applies to the go command's view of the source; the
  compiler and runtime are Go's.

## 7. TSL and OCSP

Packages `tsl` and `ocsp` decide which certificates a product trusts, so
their checks are security checks. What they do, and what they leave to
the product:

- **XML parsing.** The TSL parser is Go's `encoding/xml` tokenizer with a
  tree of its own: DTDs (and with them entity expansion) are rejected, as
  are encodings other than UTF-8, undeclared namespace prefixes,
  duplicate attributes, duplicate `Id` values and nesting deeper than 64
  levels. Attribute values with tabs or line breaks are rejected because
  the parser doesn't normalize them as XML 1.0 requires, which would make
  canonicalization differ from the signer's.
- **XML signature.** Exactly one `ds:Signature` child of the root; exactly
  one reference to the whole document (`URI=""`, enveloped-signature and
  exclusive canonicalization); other references only to elements inside
  that signature (the XAdES signed properties). Every digest must match.
  The data the TSL returns comes from the same parsed tree that was
  canonicalized, never from a second parser, so a signature-wrapping
  document can't show the signature check one content and the caller
  another. Comments are not signed (exclusive canonicalization without
  comments) and are skipped when text is read. The canonicalization
  is checked against libxml2 on real TSLs and fuzzed
  (`FuzzCanonicalize`).
- **Trust anchor and signer.** `TSL.Verify` trusts only the anchors it
  is given; the signer certificate must be issued by one of them, valid,
  with nonRepudiation and id-tsl-kp-tslSigning. Storing the anchor
  securely, and importing a new one only through `tsl.Updater` (or after
  your own checks), is the product's job.
- **OCSP.** `ocsp.Response.Verify` trusts only the responder
  certificates it is given (from the TSL); certificates in the response
  are ignored. A response whose responder ID matches none of them fails
  with `OCSP_CERT_MISSING`. Times are checked against the local clock
  with the tolerances of GS-A_5215: the clock must be right.
- **Availability.** A product that can't reach the TSL or an OCSP
  responder rejects certificates (fail closed) unless it sets
  `TolerateOCSPFailure`, and loses its trust space when the TSL's
  NextUpdate and grace period have passed (`tsl.Updater.Current` returns
  nil). Plan monitoring for both.
- **Not covered:** the XML schema check is a structural check written
  from the schema of ETSI TS 102 231, not a general XML Schema
  validator; QES checks (BNetzA-VL, TUC_PKI_030) and CRL-based checks of
  the TSL are not implemented.

## 8. The ivory test tool

`cmd/ivory` is a diagnostic tool for test environments, and it is
experimental. It uses the library's checks, but several of its commands
report a failed check instead of acting on it, on purpose:

- **Reports, not decisions.** `client` completes the handshake, with
  your client certificate if one fits, and sends the `-http` request
  before it checks the server's certificate; a failed check shows in the
  report and the exit status (3), after the fact. `probe` checks no
  server certificate before it sends its ClientHellos and reports the
  chains it saw. `server` accepts any client certificate whose key the
  client proves it holds, and only reports its check. Don't use these
  commands to send anything to a server you don't trust.
- **Where a check decides.** `tunnel` and `proxy` check the server's
  certificate before any data passes and close the connection when the
  check fails; `-verify none` turns the check off and says so in every
  report. `reverse` with `-client-auth request` or `require` fails the
  handshake of a client whose certificate fails the check, and resumes
  no sessions, so every connection is checked.
- **Trust.** `-env` trusts the TSL of that environment: the TSL
  signature is checked against a trust anchor whose SHA-256 fingerprint
  is pinned in the tool, on every start, also for a cached TSL. The
  fingerprints are those that the TSL service publishes; confirm them
  through an independent channel before you rely on a result (gemSpec_PKI
  GS-A_4640). `-trust-anchor` replaces the pinned anchor with the file
  you give, and `-ca` trusts the given CA certificates without TSL or
  OCSP. The TSL cache in your user cache directory is not protected
  beyond the TSL's signature: whoever can write to it can put an older
  TSL there that is still valid (`-refresh-tsl` downloads the current
  one).
- **Plain text on the local side.** `tunnel` and `proxy` accept plain
  connections and use your client certificate for them; `reverse` sends
  plain text to its backend. They accept only loopback addresses on the
  plain side unless you give `-allow-remote`: then anyone who can reach
  that address can use your identity, or read the backend traffic.
  `proxy` connects only to targets that match an `-allow` rule.
- **Secrets on disk.** `-key` files hold unencrypted private keys, as
  the tool reads them; use test identities. `-keylog` files (created
  with mode 0600) contain the session secrets: with one, anyone who has
  a capture of the traffic can decrypt it. Delete them after use. A
  proxy password in `-proxy` is visible in the process list; reports
  name the proxy without it.
- **The production environment.** Products in the production
  environment serve patients. `client`, `probe`, `tunnel` and `proxy`
  refuse `-env pu` without `-allow-pu`; use it only with the operator's
  permission. `probe` makes about 90 connections and sends unusual
  ClientHellos: probe only servers you may test.
