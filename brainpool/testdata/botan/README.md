# Botan test vectors

Three test vector files of the Botan cryptography library, vendored
unchanged. `kat_test.go` uses their brainpoolP256r1, brainpoolP384r1 and
brainpoolP512r1 cases:

| File | Brainpool cases | Test |
|---|---|---|
| `ecc_var_point_mul.vec` | 63 per curve: k·P for points P other than the generator (compressed points, generated with OpenSSL) | `TestBotanVarPointMul` |
| `ecc_base_point_mul.vec` | 2 per curve: k·G, the keys of RFC 6932, Appendix A | `TestBotanBasePointMul` |
| `ecdsa_rfc6979.vec` | 10 per curve: deterministic ECDSA (RFC 6979), two messages with SHA-1, SHA-224, SHA-256, SHA-384 and SHA-512 | `TestBotanRFC6979` |

| Item | Value |
|---|---|
| Source | https://github.com/randombit/botan, folder `src/tests/data/pubkey/` |
| Commit | `f745ae9cb39829a4f3219d8873ff53b8b6c24d0f` (2026-10-09) |
| License | BSD-2-Clause (`LICENSE`, Botan's `license.txt` from the same commit) |
| Checksums | `SHA256SUMS`; `TestBotanPinned` checks them |

To update, pick a new commit and replace the files:

```sh
C=<commit>
for f in ecc_var_point_mul.vec ecc_base_point_mul.vec ecdsa_rfc6979.vec; do
  curl -fsSO "https://raw.githubusercontent.com/randombit/botan/$C/src/tests/data/pubkey/$f"
done
curl -fsS -o LICENSE "https://raw.githubusercontent.com/randombit/botan/$C/license.txt"
sha256sum *.vec > SHA256SUMS
```

Then update the commit above and run the tests; they check the number of
cases per curve, so adjust those counts if Botan adds cases.
