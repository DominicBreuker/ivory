# Wycheproof test vectors

The Brainpool vectors of Project Wycheproof, vendored unchanged for
`brainpool` and `x509util` tests.

| Item | Value |
|---|---|
| Source | https://github.com/C2SP/wycheproof, folder `testvectors_v1/` |
| Commit | `12fd3aaf33eb5fa1f52e026912ee00c054f9d984` (2026-10-06) |
| License | Apache 2.0 (`LICENSE`, copied from the same commit) |
| Checksums | `SHA256SUMS`; `TestWycheproofPinned` checks them |

Files: ECDSA with SHA-2 (ASN.1 DER and IEEE P1363 `r || s`), ECDSA with
SHA-3 (ASN.1 DER), and ECDH (public keys as SubjectPublicKeyInfo) for
brainpoolP256r1, brainpoolP384r1 and brainpoolP512r1.

To update, pick a new commit and replace the files:

```sh
C=<commit>
for f in $(ls *.json); do
  curl -fsSO "https://raw.githubusercontent.com/C2SP/wycheproof/$C/testvectors_v1/$f"
done
sha256sum *.json > SHA256SUMS
```

Then update the commit above and run the tests.
