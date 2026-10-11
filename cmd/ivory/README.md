# ivory: a TLS test tool for the TI

`ivory` is a TLS client, server and prober with Brainpool support, for
testing TI products (Konnektor, card terminals, Fachdienste, test tools)
against each other and against ivory. It shows what a peer offers, what a
handshake negotiates, and the peer's certificate read the TI way:
certificate type, roles, key, and the check against the TSL with OCSP.

| Command | What it does |
|---|---|
| `ivory client host[:port]` | connects once and reports the handshake, the server's certificate chain and what it asked of the client |
| `ivory server` | accepts connections and reports, for each, the client's ClientHello (versions, cipher suites, groups, signature schemes, extensions, JA3), the result and the client certificate |
| `ivory probe host[:port]` | finds out what a server supports, with many handshakes that each offer less |
| `ivory tunnel host[:port]` | accepts plain TCP connections on localhost and forwards each over TLS to the server |
| `ivory proxy -allow …` | an HTTP proxy on localhost that sends requests for `http://` URLs over TLS to their server |
| `ivory reverse -backend host:port` | accepts TLS connections and forwards the plain text of each to a local server |

Every command takes `-json` for a machine-readable report and `-help` for
its flags. Exit status: 0 success, 1 a failed handshake or an error, 2 a
usage error, 3 (client) a server certificate that fails the TI check.

> **Status: experimental.** `ivory` is tested against itself and has
> been run against TI services that are reachable from the internet, but
> not yet against Konnektoren, card terminals or other TI products inside
> the TI networks. Its flags, the text reports and the fields of the
> `-json` output may change in any version. Please
> [report](../../README.md#feedback) what you see with real products,
> successes included.

## Build

`ivory` needs the ivory overlay, so `go install` doesn't work: build it
in a checkout of ivory, with the toolchain and overlay of the
[user guide](../../docs/user-guide.md#2-get-the-toolchain-and-the-overlay):

```sh
git clone https://github.com/DominicBreuker/ivory ~/ivory
cd ~/ivory
scripts/ivory-overlay toolchain
scripts/ivory-overlay build -profile core
eval "$(scripts/ivory-overlay env -profile core)"
go build -o ivory ./cmd/ivory
./ivory -help
```

A binary built without the overlay and the `ivory` build tag only prints
`ivory: built without the ivory overlay`. The binary needs nothing at run
time: copy it to any linux/amd64 machine.

With `-profile kt` instead of `core`, the server sends the card
terminal's CertificateRequest (one certificate type per cipher suite,
and only the signature schemes of that type) and the client lists ECDSA
suites before RSA suites, as an eHealth-KT and a Konnektor do.

## First steps

Try `ivory` on your own machine first, with the test certificates in
`testdata/pki/` (a Brainpool test CA with a server and a client
certificate; [testdata/pki/README.md](../../testdata/pki/README.md)).
In one terminal, a server with a Brainpool identity:

```sh
./ivory server -addr 127.0.0.1:4433 \
    -cert testdata/pki/bp256-server.pem -key testdata/pki/bp256-server.key
```

In a second terminal, a client that checks the server against the test
CA and presents a Brainpool client certificate:

```sh
./ivory client -ca testdata/pki/bp256-ca.pem \
    -cert testdata/pki/bp256-client.pem -key testdata/pki/bp256-client.key \
    localhost:4433
```

The client reports TLS 1.2 with `TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256`,
the server's chain with its brainpoolP256r1 key, `TI check … result ok`
and a failed web PKI check, which is expected here: that check uses the
system's roots, which don't contain the test CA. The server reports the
client's ClientHello and its certificate. The `ti` profile
prefers P-256 for the key exchange, as the TI's presets do; add
`-groups brainpoolP256r1` to the client to see Brainpool ECDHE. Add
`-trace` to either side to see every record.

Then give curl Brainpool TLS. Restart the server with `-http`, so that it
answers HTTP requests, start a tunnel from `localhost:8443` to it in the
second terminal, and send a request through the tunnel from a third:

```sh
./ivory server -addr 127.0.0.1:4433 -http -client-auth none \
    -cert testdata/pki/bp256-server.pem -key testdata/pki/bp256-server.key
./ivory tunnel -ca testdata/pki/bp256-ca.pem localhost:4433
curl --connect-to ::localhost:8443 http://localhost/
```

curl speaks plain HTTP to the tunnel; the tunnel makes the TLS
connection, checks the server certificate and reports it. If your shell
sets `http_proxy`, add `--noproxy '*'` to curl.

Against TI products, replace `-ca` by `-env tu` or `-env ru` (the trust
space of the TSL, with OCSP) and use your own test card's identity
([Identities](#identities)). The commands below show what else each
command can do.

## Environments and trust

`-env tu`, `-env ru` or `-env pu` selects the TI test, reference or
production environment. ivory downloads that environment's TSL from the
TSL service, checks its signature against the trust anchor whose SHA-256
fingerprint is pinned in `env.go` (GEM.TSL-CA28 TEST-ONLY for TU and RU,
GEM.TSL-CA3 for PU), and caches it in the user cache directory
(`~/.cache/ivory/tsl/<env>/` on Linux) until its NextUpdate;
`-refresh-tsl` downloads it again. A cached TSL is checked again on every
start. The downloads go to `download-test.tsl.ti-dienste.de` (TU, and the
anchor of TU and RU), `download-ref.tsl.ti-dienste.de` (RU) and
`download.tsl.ti-dienste.de` (PU) over HTTPS, the OCSP requests over
plain HTTP to the responder that the TSL names for the issuing CA. Allow
them in your firewall, or use `-proxy`. An OCSP responder that can't be
reached fails the TI check with the error in the report; `-no-ocsp`
skips the request. The peer's certificate must then be
issued directly by a CA of the TSL (no path building), the CA's status in
the TSL must allow it, and the OCSP responder that the TSL names for the
CA must report it good (`-no-ocsp` skips that request).

Other trust sources:

- `-tsl file-or-url` with `-trust-anchor cert`: a TSL of your own, such as
  one of a local test PKI;
- `-ca cert.pem` (repeatable): CA certificates that may issue the peer's
  certificate, without TSL or OCSP.

**Production (PU).** Products in the production environment serve
patients. `client` and `probe` refuse `-env pu` unless you add
`-allow-pu`; use it only with the operator's permission. The TU and RU
are the places to test.

## Identities

`-cert chain.pem -key key.pem` sets a local identity; repeat the pair for
more than one (for example an RSA and a Brainpool identity on a server).
Keys may be Brainpool, NIST ECDSA, RSA or Ed25519 keys, in PKCS #8 or
SEC 1 PEM. Identities from a PKCS #12 file:

```sh
openssl pkcs12 -in identity.p12 -nodes -legacy -out identity.pem
ivory client -cert identity.pem -key identity.pem host:port
```

A client picks the first identity that fits the server's
CertificateRequest, or the first one if none fits. A server without
`-cert` serves fresh self-signed identities (brainpoolP256r1, P-256 and
RSA 2048) for the names in `-name`, so that every client gets a
certificate; no TI client trusts them, but the ClientHello report is
complete before the client checks the certificate.

## TLS profiles

| `-profile` | Versions | Groups | Signature schemes |
|---|---|---|---|
| `ti` (default) | TLS 1.2 | P-256, P-384, brainpoolP256r1, brainpoolP384r1; the TI cipher suites | crypto/tls's defaults |
| `tls13` | TLS 1.3 | brainpoolP256r1tls13, brainpoolP384r1tls13, brainpoolP512r1tls13, P-256, P-384 | those of `tlsutil.SignatureSchemes` (RSA-PSS, ECDSA NIST and Brainpool) |
| `wide` | TLS 1.2 and 1.3 | X25519MLKEM768, X25519, the NIST curves and all Brainpool groups | crypto/tls's defaults and the Brainpool TLS 1.3 schemes |

`-tls`, `-suites`, `-groups` and `-sigalgs` override the profile, for
example `-groups brainpoolP256r1 -suites ECDHE_ECDSA_WITH_AES_128_GCM_SHA256`
(names, or numbers such as `0xc02b` and `26`). A server with both versions
answers clients that support Brainpool only with the TLS 1.2 code points
(Windows SChannel) in TLS 1.2 (`tlsutil.TLS12Fallback`).

## Client

```sh
ivory client -env tu -cert smcb.pem -key smcb.pem host:443
ivory client -env ru -profile tls13 -trace host:443
ivory client -ca test-ca.pem -http / localhost:4433
```

The report shows the negotiated version, cipher suite, group and (in
TLS 1.2) the server's signature scheme, the ServerHello's extensions, each
certificate of the chain (subject, issuer, validity, key, key usages, TI
certificate type from the policies, roles and registration number from
the admission extension, names, OCSP addresses), the TI check of the
leaf and a web PKI check: the chain against the system's roots for the
server name, as a browser would check it (TI services reachable from the
internet use certificates of public CAs). A failed handshake still
reports the alerts and what the server sent before it. `-http path` sends
a GET after the handshake.

## Server

```sh
ivory server -addr :4433 -client-auth require -env tu
ivory server -addr :4433 -cert kt-ecc.pem -key kt-ecc.key -cert kt-rsa.pem -key kt-rsa.key -trace
```

`-client-auth` is `none`, `request` (the default; a client may send no
certificate) or `require`. The server accepts any certificate the client
proves possession of and reports the TI check; the check never fails the
handshake. After the handshake it reads what the client sends until the
client closes the connection or `-idle` passes; `-http` answers an HTTP
request with the report. `-once` exits after one connection.

## Probe

```sh
ivory probe -env ru host:443
ivory probe -only versions,suites -trace host:443
```

A single handshake shows only what both sides agreed on. The probe sends
ClientHellos of its own and reads the server's first flight, so it needs
no client certificate for most sections:

- **versions**: SSL 3.0 to TLS 1.2 by `legacy_version`, TLS 1.3 by
  `supported_versions`;
- **suites**: offer all, take the server's choice out, repeat; then the
  reversed list shows whether the server or the client order decides;
- **groups**: TLS 1.2 groups one by one (the ServerKeyExchange names the
  curve), and TLS 1.3 groups one by one with an empty `key_share`, which
  a server answers with a HelloRetryRequest that names its group; both
  with the order test;
- **sigalgs**: TLS 1.2 schemes one by one (the ServerKeyExchange names
  the scheme); TLS 1.3 schemes with full crypto/tls handshakes, since the
  server's CertificateVerify is encrypted (a server that has no
  certificate for the scheme refuses the ClientHello). These handshakes
  offer one scheme in `signature_algorithms` but also the PKCS #1 v1.5
  and SHA-1 schemes in `signature_algorithms_cert`, since some servers
  check their own certificate's signature against it; a server with an
  ECDSA certificate signed with another hash than the probed scheme may
  still refuse;
- **extensions**: extended master secret, secure renegotiation, session
  tickets and IDs, OCSP stapling, SCT, ALPN, encrypt-then-MAC, compression;
- **fallback**: `TLS_FALLBACK_SCSV` with a lower version.

It also lists every certificate chain the server presented and under which
conditions (a card terminal has an RSA and an ECC identity), the
CertificateRequests of TLS 1.2 and 1.3 (certificate types, signature
schemes, acceptable CAs), and observations against the TI settings of the
`ti` presets (cipher suites, groups, Brainpool in TLS 1.3). These are
observations, not a conformance verdict: which requirements apply depends
on the product type.

A probe of a TLS 1.2 and 1.3 server takes about 90 connections. `-delay`
(default 100 ms) spaces them out; `-timeout` bounds each. Probe only
servers you may test.

## Proxy

`client`, `probe`, `tunnel` and `proxy` can connect through a proxy,
which relays the TLS bytes unchanged:

```sh
ssh -D 1080 jumphost                       # a SOCKS5 proxy on localhost:1080
ivory probe -proxy socks5h://localhost:1080 host:443
ivory client -proxy http://user:password@proxy.example:3128 host:443
ivory tunnel -proxy socks5h://localhost:1080 host
```

`-proxy` takes `http://` (HTTP `CONNECT`), `socks5h://` (SOCKS5; the
proxy resolves the host name, as `ssh -D` and curl's `socks5h` do) or
`socks5://` (SOCKS5; the name is resolved locally), each with optional
`user:password@`. `-proxy direct` connects directly. `-proxy env` (the
default) takes the proxy from `HTTPS_PROXY` (or `https_proxy`), else
from `ALL_PROXY` (or `all_proxy`); either may name a SOCKS5 proxy, and a
bare `host:port` means HTTP. Targets listed in `NO_PROXY` (or
`no_proxy`) connect directly: `*`, a domain (`example.org` or
`.example.org`, which both match the domain and its subdomains),
`host:port`, an IP address or a CIDR range. Loopback targets never go
through the proxy. The report names the proxy. A proxy that terminates
TLS itself shows up as its own certificate chain in the report.

The TSL and OCSP downloads of `-env` and `-tsl` use the same proxy:
behind `ssh -D`, one `-proxy socks5h://localhost:1080` (or
`ALL_PROXY=socks5h://localhost:1080`) covers everything. `server` and
`reverse` take `-proxy` for these downloads only.

## Tunnel and proxy: Brainpool TLS for other tools

`tunnel` and `proxy` let tools without Brainpool support, such as curl,
a browser or a program in another language, talk to Brainpool TLS
servers: they speak plain text to `ivory` on the local machine, and
`ivory` makes the TLS connection with the flags of `client` (`-profile`,
`-groups`, `-cert`/`-key`, `-env`, `-proxy`, `-keylog`, `-trace`).

```sh
# any TCP protocol: localhost:8443 -> host:443
ivory tunnel -groups brainpoolP256r1 host
curl --connect-to ::localhost:8443 http://host/path

# HTTP: requests for http://host[:port]/... go over TLS to host:port (default 443)
ivory proxy -allow host -allow '*.example.org:443'
curl -x http://localhost:8080 http://host/path
```

With curl, `--connect-to` keeps the URL's host name in the Host header.
If `NO_PROXY` lists the target, curl bypasses `-x`; add `--noproxy ''`.

Each upstream connection is reported as it opens (version, cipher suite,
group, the server certificate and its check, the client certificate
sent) and when it closes (bytes each way); `proxy` also reports each
request with its status. `-json` prints one JSON object per event.
Connections are kept open for reuse (`proxy`) and resume their TLS
sessions where the server allows it.

**The server certificate is checked before any data passes**, and a
connection whose check fails is closed: with `-env`, `-tsl` or `-ca` the
TI way (as in `client`, against the TSL with OCSP or against the CA
files, without a name check, since TI certificates often carry none),
otherwise against the system's roots for the server name (`-verify
webpki`), as TI services reachable from the internet use certificates of
public CAs. `-verify none` turns the check off and says so in every
report; use it only for tests. OCSP answers are reused for ten minutes.

Safety:

- The local side is plain text, so `-listen` takes only loopback
  addresses (`localhost`, `127.0.0.1`, `[::1]`); `-allow-remote` lifts
  that, for example in a container whose port is published only to the
  host. Anyone who can reach the listener can use your client
  certificate.
- `proxy` connects only to targets that match an `-allow` rule (`host`,
  `host:port`, `*.domain`, `*.domain:port`, or `*` for any), so that it
  is no open proxy; it refuses `CONNECT`, since the client would then do
  the TLS itself.
- `-env pu` needs `-allow-pu`, as for `client` and `probe`.

`tunnel` and `proxy` stop on SIGINT or SIGTERM.

## Reverse: Brainpool TLS for other servers

`reverse` is the other direction: it accepts TLS connections with
Brainpool certificates and key exchange and forwards the plain text of
each to a server that has no Brainpool support, such as a test service
written in another language:

```sh
# TLS on localhost:8443 -> plain text to localhost:9000
ivory reverse -cert server.pem -key server.key -backend localhost:9000

# with client certificates checked against the TSL of the RU
ivory reverse -cert server.pem -key server.key -backend localhost:9000 \
    -env ru -client-auth require
```

It takes the TLS flags and identities of `server` (`-profile`,
`-groups`, `-cert`/`-key`, repeatable for an RSA and an ECC identity;
without `-cert` it generates self-signed ones for `-name`), and `-keylog`,
`-trace` and `-json`. Each connection is reported when its handshake ends
(version, cipher suite, group, the client certificate and its check)
and when it closes (bytes each way).

`-client-auth` decides about client certificates: `none` (the default)
asks for none, `request` asks for one and checks it if sent, `require`
fails the handshake without one. `request` and `require` need `-env`,
`-tsl` or `-ca`: a client certificate that fails the check (TI way, as
in `tunnel`) fails the handshake, so the backend sees only connections
whose certificate passed. The backend can't see who connected; the
report can. Sessions aren't resumed, so every connection is checked.

Safety:

- The backend leg is plain text, so `-backend` takes only loopback
  addresses; `-allow-remote` lifts that. Keep the backend on the same
  machine, or in a network only you can reach.
- `-listen` is the TLS side. It defaults to `localhost:8443`; give it
  another address (`-listen :8443` for all interfaces) to accept TI
  clients from the network. Without client certificates
  (`-client-auth none`) anyone who can reach that port reaches the
  backend, so `reverse` warns at startup when `-listen` is not a
  loopback address and `-client-auth` is `none`.
- Like `server`, `reverse` connects to no product, so `-env pu` (to
  check the certificates of production clients) needs no `-allow-pu`.

`reverse` stops on SIGINT or SIGTERM.

## Trace

`-trace` prints every TLS record as it passes: direction, record type,
version and length, and each plaintext handshake message decoded field by
field (ClientHello and ServerHello with all extensions, certificates,
ServerKeyExchange, CertificateRequest, alerts). `-hex` adds a hex dump of
every record. With `-json`, the trace is part of the JSON report.

Everything after the ChangeCipherSpec (TLS 1.2) or the ServerHello
(TLS 1.3) is encrypted. `-keylog file` writes the session secrets in the
NSS key log format; Wireshark decrypts a capture with it (Preferences,
Protocols, TLS, "(Pre)-Master-Secret log filename"). In TLS 1.3, the
client's report also shows the server's CertificateRequest (from
crypto/tls), which the trace can't decode.
