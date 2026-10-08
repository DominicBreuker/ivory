# Constant-time review: `brainpool`

Review of the non-test code of `brainpool/` (2026-10-08), against this
checklist: no secret-dependent branches or memory indices, only `bigmod`
functions that aren't VarTime on secrets, `crypto/subtle` for
comparisons, no `math/big`. Every change to the package updates this
review. How to reproduce the checks: [the end of this document](#reproduce).

**Verdict:** no secret-dependent branch, index or variable-time call found.
The remaining branches on secret-derived values are rejection loops with
negligible or secret-independent probability (listed below). This is a
self-review by the developers; an external review is still needed before
production use ([security.md](security.md)).

## What counts as secret

| Secret | Where |
|---|---|
| private scalar d | `PrivateKey.d`, `PrivateKey.dn`; `NewPrivateKey`, `ECDH`, `sign`, the nonce generator |
| nonce k and k⁻¹ | `sign`, `nonceGenerator.next` |
| ephemeral ECDH keys and shared secrets | `GenerateKey`, `ECDH`, `Encapsulate`, `Decapsulate` |
| intermediate points of k·G and d·Q | `scalarMult`, `addPoints`, `affine` |

Public: curve parameters, public keys, digests (the message is public in
ECDSA), signatures, the hedging randomness after use, lengths.

## Building blocks

| Item | Constant time? | Why |
|---|---|---|
| `bigmod.Nat.Add`, `Sub`, `Mul`, `Mod` | yes | fixed loops over the modulus' limbs; reduction with `maybeSubtractModulus` (masked `assign`); Montgomery multiplication without early exit (`filippo.io/bigmod` v0.1.0 `nat.go`) |
| `bigmod.Nat.Exp` | yes in the base; the exponent is public | 4-bit fixed window, table lookup by masked `assign` over all 15 entries; the exponents are p−2 and n−2 |
| `bigmod.Nat.SetBytes` | yes | `setBytes` loops over the input length; the range check `cmpGeq` is masked; the returned error tells only whether the value is in range |
| `bigmod.Nat.SetOverflowingBytes` | leaks the bit length of the top limb | used only on digests (`hashToNat`), which are public |
| `bigmod.Nat.Bytes` | yes for our sizes | its `if limb == 0` branch is reached only when the Nat is longer than the modulus' byte size; 32, 48 and 64 bytes are whole limbs on 32- and 64-bit platforms |
| `bigmod.Nat.Equal`, `IsZero` | yes | `ctEq` over all limbs |
| `bigmod` VarTime functions | not called | no call to `…VarTime`, `InverseVarTime`, `GCDVarTime`, `DivShortVarTime`, `ExpShortVarTime` anywhere; `Modulus.BitLen` (VarTime inside) is only called on the public moduli |
| `condSwap` (ours) | yes | `mask = −swap`; XOR-AND-XOR on every limb of both operands. The compiled amd64 code has no data-dependent branch (`go build -gcflags=-S ./brainpool`, function `condSwap`) |
| `addPoints` (ours) | yes | a fixed sequence of 40 field operations (Renes–Costello–Batina 2016, Algorithm 1), complete for all inputs: no special case for doubling, inverses or the point at infinity |
| `scalarMult` (ours) | yes | Montgomery ladder over all 8·len(k) bits of the fixed-length scalar, one `condSwap` and two `addPoints` per bit, whatever the bit; the bit is extracted with shifts and masks; memory accesses depend only on the bit position |
| `affine` (ours) | yes | inversion by Fermat (`Exp` with p−2), two multiplications; the infinity flag is returned as a value |
| HMAC-DRBG (`crypto/hmac`, SHA-2) | yes | the standard library's SHA-2 is data-independent; the loop counts depend only on lengths |
| `PrivateKey.Equal`, `PublicKey.Equal` | yes | `crypto/subtle.ConstantTimeCompare` |
| `math/big` | not imported | `brainpool` imports only `crypto`, `crypto/hmac`, `crypto/rand`, `crypto/subtle`, `encoding/hex`, `errors`, `hash`, `io`, `filippo.io/bigmod` and cryptobyte (`go list -f '{{.Imports}}' ./brainpool`). `math/big` is linked in only through cryptobyte's integer parsing, which `brainpool` uses only to parse public signatures (into byte slices). `x509util` imports `crypto/x509`, which uses `math/big` for the keys it handles itself (RSA, NIST curves); Brainpool scalars never pass through it |

## Function by function

| Function | Secret-dependent control flow | Assessment |
|---|---|---|
| `GenerateKey` | rejection loop: retry if the random candidate is ≥ n or 0 | leaks only the number of rejected candidates, which are independent of the accepted key |
| `NewPrivateKey` | `err != nil \|\| dn.IsZero() == 1` | rejects invalid input; the time of a valid key's computation doesn't depend on its value. The `panic` branches are unreachable for valid d (d·G ≠ O, d·G on the curve) |
| `ECDH` | `ok != 1` → error | O occurs only for an invalid peer key, which `NewPublicKey` already rejects; public outcome |
| `sign` | retry if r = 0 or s = 0 | probability about 2⁻²⁵⁶ per attempt; public outcome |
| `nonceGenerator.next` | retry if the candidate is ≥ n or 0 (RFC 6979, step h.3) | the rejected candidate is discarded; the accepted k is not influenced by the timing |
| `hashToNat`, `bits2int` | branches on lengths and on the digest's top limb | digest and lengths are public |
| `encodeSignature` | strips leading zero bytes of r and s | r and s are the public signature |
| `verify`, `VerifyASN1`, `VerifyRaw`, `parseSignature`, `NewPublicKey`, `pointFromAffine`, `onCurve` | many | public inputs only; constant-time code is used anyway |
| `Decapsulate`, `Encapsulate` | errors on invalid peer points | public outcome |

## Not covered

- **Erasure.** Secrets stay in memory until the garbage collector reuses
  it; Go offers no reliable zeroing ([security.md](security.md), Section 4).
- **Microarchitecture.** The review is at source and assembly level. It
  assumes that `MULQ`/`ADCQ` have data-independent timing on the target
  (true for current x86-64 cores, per the usual assumptions of Go's
  `crypto/internal/fips140/bigmod`) and doesn't consider power or EM
  side channels.
- **Allocation.** The code allocates on the heap per operation; the
  pattern depends only on lengths, but GC pauses add noise, not signal.
- **Dependencies.** `filippo.io/bigmod` is trusted as reviewed by the Go
  team (it is the standard library's `crypto/internal/fips140/bigmod`);
  the review checked how we call it, not its internals beyond the
  functions listed.

## Timing check

`TestTimingLeaks` (opt-in, `IVORY_TIMING=1`) compares the ladder's time
for a scalar with a single bit set against random scalars with Welch's t
test (dudect). On 2026-10-08 all curves gave |t| ≤ 1.06 with 3,000
samples; a deliberately leaky ladder (one extra point addition per 1 bit)
gave t = −42.

## Reproduce

```sh
go list -f '{{.Imports}}' ./brainpool             # no math/big
grep -n 'VarTime' brainpool/*.go | grep -v _test   # no output: no VarTime calls
go build -gcflags=-S ./brainpool 2>&1 | less       # assembly of condSwap
IVORY_TIMING=1 go test -run TestTimingLeaks -v ./brainpool
```
