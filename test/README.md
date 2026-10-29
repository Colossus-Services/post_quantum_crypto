# Tests

```sh
dart test                          # everything the VM can run
dart test -x slow -x interop       # what most CI shards run
dart test -t vectors               # official known-answer vectors only
dart test -p chrome test/browser   # browsers (add -c dart2wasm for Wasm)
```

Tags are declared in `dart_test.yaml`:

| Tag | Meaning |
|---|---|
| `vectors` | Official known-answer vectors read from `test/vectors/` (VM only: loaded with `dart:io`). |
| `interop` | Cross-implementation tests against OpenSSL ≥ 3.5; they skip themselves when none is found. |
| `fuzz` | Seeded mutation fuzzing of every parser. |
| `slow` | Long-running tests (large files, SLH-DSA signing, SLH-DSA "s" key checks). |
| `platform` | Tests touching the file system, permissions, processes or isolates; CI also runs these on macOS and Windows. |
| `browser` | Tests that run in browsers (dart2js and dart2wasm). |
| `version` | The test pinning `postQuantumCryptoVersion` to `pubspec.yaml`. |

## Directories

### `unit/`

Focused tests of one component or rule.

- `expanded_key_checks_test.dart`: the consistency checks on imported expanded private keys, one key component at a time:
  - ML-DSA (`t = A·s1 + s2`);
  - SLH-DSA (`PK.root` recomputation, including the `verifySlhDsaKey` opt-out);
  - ML-KEM (`H(ek)` and pairwise consistency).

  Components the standards leave unconstrained (ML-DSA's K, SLH-DSA's SK.prf, ML-KEM's z) are pinned down as uncheckable.
- `key_serialization_test.dart`: key ids, `PQCR` key records, DER/PEM (PKCS#8, SPKI), password-protected keys and password-based data encryption.
- `key_commitment_test.dart`: an "invisible salamanders" attack: one AES-GCM ciphertext valid under two data keys is rejected thanks to the envelope's key commitment.
- `api_edge_cases_test.dart`: edges of the public API (raw key import, signature policy, canonical-map limits, password parameters, encodings, `FileKeyStorage`).
- `review_regressions_test.dart`: regression tests for findings of earlier code reviews.
- `misc_test.dart`: text encodings and the version pin.

### `integration/`

End-to-end workflows through the public engine API.

- `envelope_test.dart`: ML-KEM envelopes: single and multiple recipients, authenticated context, tampering, policy.
- `streaming_test.dart`: streaming encryption: round trips over irregular slices, attacks on the chunk sequence (reordering, truncation, extension), limits.
- `signatures_test.dart`: raw FIPS 204 signatures, detached signatures, signed artifacts and manifests, trust evaluation.
- `hybrid_test.dart`: hybrid (X-Wing) key establishment, transcript binding, downgrade and misdirected-message rejection.
- `key_store_test.dart`: `KeyStore` over `FileKeyStorage`, including that a password-protected store holds no plaintext seeds.
- `file_crypto_test.dart`: file encryption and signing. A truncated or cancelled file operation publishes no output, and memory use does not grow with file size.

### `vectors/`

Known-answer tests against published vectors (tag `vectors`), plus the package's own format vectors. Each third-party file is a trimmed subset of its upstream source, fetched by `dart run tool/fetch_vectors.dart`. `PROVENANCE.md` lists every source URL and the SHA-256 of the full upstream file. The vector files are in the repository, not in the published package.

- `pq_kat_test.dart`: NIST ACVP for ML-KEM and ML-DSA (see below), and the X-Wing draft vectors.
- `slhdsa_kat_test.dart`: NIST ACVP for SLH-DSA (see below).
- `wycheproof_mlkem_test.dart`, `wycheproof_mldsa_test.dart`: C2SP Wycheproof ML-KEM and ML-DSA.
  - `valid` tests must reproduce the published values byte for byte.
  - Every other test must be rejected.
  - Keys go through the engine's import functions, as an application's would.
- `symmetric_kat_test.dart`: Wycheproof AES-256-GCM, ChaCha20-Poly1305, HKDF and HMAC (SHA-256/384), on both symmetric backends. Also FIPS 180-4 and FIPS 202 examples, Argon2id (RFC 9106 §5.3) and X25519.
- `hpke_kat_test.dart`: HPKE (RFC 9180 key schedule and AEAD context) with the ML-KEM and X-Wing KEMs, against the draft-ietf-hpke-pq vectors.
- `rfc_x509_examples_test.dart`: the Appendix C keys of RFC 9881 (ML-DSA in X.509) and RFC 9935 (ML-KEM in X.509).
  - Every key is imported and re-exported byte for byte.
  - The deliberately inconsistent C.4 keys must be rejected.
- `format_vectors_test.dart`: the package's own format v2 vectors (`post_quantum_crypto_v2.json`).
  - The stored objects must decrypt and verify.
  - `format_vectors.dart` must still reproduce them byte for byte (format stability).
  - Regenerate them with `dart run test/vectors/generate_format_vectors.dart`.

### `browser/`

`cross_platform_test.dart` has no `dart:io`, so it runs on the VM and in browsers (dart2js and dart2wasm). It holds three groups:

- **Compact official vectors.** Seeds plus the SHA-256 of large outputs, for X-Wing, ML-KEM-768, ML-DSA-65, AES-256-GCM, ChaCha20-Poly1305, HKDF-SHA-384 and Argon2id.
- **Byte-identical serialization.** Deterministic package outputs are pinned by digest, so every platform must produce byte-identical serializations.
- **Workflow tests.** Envelopes, streaming, signatures and expanded-key checks.

### `fuzz/`

`parser_fuzz_test.dart` runs seeded mutation fuzzing of every public parser and decoder. For any input, a parser either succeeds or throws a `PostQuantumCryptoException`. It never throws `RangeError`, `TypeError`, `StateError` and the like, and it never hangs. `QC_FUZZ_ITERATIONS` raises the default of 300 iterations per target.

### `interop/`

`openssl_test.dart` checks interoperability with OpenSSL ≥ 3.5 for ML-KEM-768, ML-DSA-65 and SLH-DSA-SHAKE-128f. Encapsulations and signatures cross between the two implementations in both directions, and OpenSSL accepts the package's PKCS#8 seed keys. Set `OPENSSL` to choose the binary.

### `support/`

Helpers, not tests:

- `test_engine.dart`: a production engine, a deterministic seeded engine (`DeterministicRandom`, which lives under `test/` so production code cannot import it) and small test helpers.
- `vectors.dart`: loaders for vector files (`loadVectors`, `hex`, `acvpTests`, `wycheproofTests`).

## NIST tests

The NIST vectors are the ACVP "internal projection" files from [usnistgov/ACVP-Server](https://github.com/usnistgov/ACVP-Server/tree/master/gen-val/json-files), which carry the inputs and the expected outputs together.

Only the interfaces this package exposes are kept:

- the external/pure signature interface (no pre-hash, no `Sign_internal`);
- for SLH-DSA, the SHAKE parameter sets only.

Of each test group, the first *N* tests are kept.

| File | Standard | Parameter sets | Tests kept | What is checked |
|---|---|---|---|---|
| `acvp_mlkem_keygen.json` | FIPS 203 | ML-KEM-512/768/1024 | 10 per set | `KeyGen_internal(d, z)` reproduces `ek` and `dk`. |
| `acvp_mlkem_encapdecap.json` | FIPS 203 | ML-KEM-512/768/1024 | 10 per group, 4 groups per set | See the ML-KEM notes below. |
| `acvp_mldsa_keygen.json` | FIPS 204 | ML-DSA-44/65/87 | 10 per set | `KeyGen_internal(ξ)` reproduces `pk` and `sk`, and the package's own `t = A·s1 + s2` recovers `pk` from `sk`. |
| `acvp_mldsa_siggen.json` | FIPS 204 | ML-DSA-44/65/87 | 6 per group, deterministic and hedged | Signatures are reproduced byte for byte (`rnd = 0^32`, or the given `rnd`). |
| `acvp_mldsa_sigver.json` | FIPS 204 | ML-DSA-44/65/87 | 15 per set | `verify` matches `testPassed`, including the listed failure reasons (modified message, signature, `z`, hint, …). |
| `acvp_slhdsa_keygen.json` | FIPS 205 | SLH-DSA-SHAKE-128s/f, 192s/f, 256s/f | 1 per set | See the SLH-DSA notes below. |
| `acvp_slhdsa_siggen.json` | FIPS 205 | SHAKE "f" sets only | 2 per set, hedged | Signatures are reproduced byte for byte with the given `additionalRandomness`. The secret key imports with the right public key, and the signature verifies through the engine. |
| `acvp_slhdsa_sigver.json` | FIPS 205 | all six SHAKE sets | 4 per set | `verify` matches `testPassed`. |

**ML-KEM encapDecap groups:**

- **encapsulation:** reproduces `c` and `K`.
- **decapsulation:** reproduces `K`, including the modified-ciphertext cases, where implicit rejection must return FIPS 203's pseudorandom `K̄` rather than an error.
- **encapsulationKeyCheck:** the stand-alone check and encapsulation must agree.
- **decapsulationKeyCheck:** the import check accepts or rejects as listed.

**SLH-DSA keyGen:**

- The secret key layout is `SK.seed ‖ SK.prf ‖ PK.seed ‖ PK.root`.
- The import check recomputes `PK.root` and yields the official public key without being given it.
- Key generation from `SK.seed ‖ SK.prf ‖ PK.seed` (Algorithm 18) reproduces the official key pair.

The subsets are kept small for running time: in pure Dart, SLH-DSA "s" key generation takes 1–2 s and "s" signing is much slower. SLH-DSA sigGen therefore covers only the "f" sets.

The ACVP vectors show **algorithm conformance**. They are not a FIPS 140 / CMVP validation (see `doc/SECURITY.md`).

For the other parameter sets and edge cases, the Wycheproof files complement ACVP:

- Wycheproof keeps every non-`valid` test.
- The ML-KEM files incorporate the CCTV edge cases: strcmp, unreduced and overflowing public keys.
