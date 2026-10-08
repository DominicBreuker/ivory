# probe: what crypto/tls puts on the wire

`probe` records the TLS details that gemSpec_Krypt and gemSpec_KT regulate
but that crypto/tls doesn't let an application configure. It needs no
Brainpool code. K5 and K7 listen on a local address for an OpenSSL peer.
Build it with the toolchain and overlay under test.

| Probe | What | Requirement | Stock Go 1.27 | Expected with ivory |
|---|---|---|---|---|
| K1 | TLS 1.2 ClientHello `cipher_suites` | A_17124-03 item 3, A_17094-02 | C02B, C02F, C02C, C030 | core: unchanged; kt: C02B, C02C, C02F, C030 (P7) |
| K2 | TLS 1.3 ClientHello suites | A_17322, A_18467 | 1301, 1302, 1303 (ChaCha20 always offered) | unchanged; the reason TI products stay on TLS 1.2 |
| K3 | TLS 1.2 CertificateRequest `certificate_types` | A_22454 | `01 40` | core: unchanged; kt: `40` on ECDSA suites, `01` on RSA suites (P6) |
| K4 | `supported_groups` with `CurvePreferences = [P-256, P-384]` | GS-A_4384-03 | 0017, 0018 | the listed groups, including 26/27 with P4 |
| K5 | a client renegotiates against a Go server | GS-A_5524 | `fatal unexpected_message` | `fatal no_renegotiation` (P0) |
| K6 | `signature_algorithms(_cert)` | A_18467, A_21275-01 | TLS 1.3 includes Ed25519 and ML-DSA; `signature_algorithms_cert` includes SHA-1 schemes | unchanged unless P5 trims them |
| K7 | TLS 1.3 server with AES-only `CipherSuites`, client offers only ChaCha20 | A_18467 | negotiates ChaCha20 | unchanged |

## Tests

`go test ./probe` checks K1–K5 in-process. K5 starts `openssl s_client`
and is skipped without OpenSSL. Its expectation depends on the `ivory`
build tag: stock Go must send `unexpected_message`, the overlay
`no_renegotiation`. K1 and K3 depend on the profile: `ivory-overlay env`
sets the build tag `ivory_<profile>`, and `expect_kt_test.go` (tag
`ivory_kt`) holds the kt expectations, `expect_test.go` those of stock Go
and core. K3 runs against a server with an ECDSA and one with an RSA
certificate.

## Run

```sh
go run ./probe                      # K1-K4, K6

# K5: renegotiation against a Go server, driven by OpenSSL. s_client starts
# a renegotiation when it reads a line "R" on its own.
go build -o /tmp/probe ./probe
/tmp/probe -k5 127.0.0.1:4483 &
python3 -c "import sys,time; sys.stdout.write('hello\n'); sys.stdout.flush(); time.sleep(1); sys.stdout.write('R\n'); sys.stdout.flush(); time.sleep(2)" |
  openssl s_client -connect 127.0.0.1:4483 -tls1_2 -msg 2>&1 | grep -E 'Alert|RENEGOTIATING'

# K7: TLS 1.3 Go server (Config.CipherSuites = AES-GCM only), OpenSSL client
# that offers only ChaCha20-Poly1305.
/tmp/probe -k7 127.0.0.1:4484 &
python3 -c "import time; time.sleep(1)" |
  openssl s_client -connect 127.0.0.1:4484 -tls1_3 \
    -ciphersuites TLS_CHACHA20_POLY1305_SHA256 2>&1 | grep 'Cipher is'
```

`python3 … time.sleep` keeps `s_client`'s stdin open; plain `sleep` works
too where it is allowed.
