## 1.0.1

### CI

- Coverage is uploaded to Codecov (`codecov/codecov-action@v7`); README
  shows the Codecov badge. `actions/checkout` upgraded to v7.

### Tests

- Added `test/unit/version_test.dart`, pinning `postQuantumCryptoVersion`
  to `pubspec.yaml` (it was referenced but missing).

## 1.0.0

Initial release.

### Added

- **Envelope encryption** with ML-KEM-512/768/1024 (FIPS 203) and X-Wing
  recipients. Each recipient's data key is wrapped with HPKE (RFC 9180,
  HKDF-SHA-384); the payload uses AES-256-GCM or ChaCha20-Poly1305. Works
  for one or many recipients.
- **Authenticated context** on every encrypted object, with
  `requiredContext` checks on decryption.
- **Rewrapping**: `rewrapEnvelope`, `addRecipients` and `removeRecipients`
  re-encrypt under a fresh data key.
- **Streaming encryption** (STREAM construction): per-chunk counter and
  final-flag nonces, progress reporting and cancellation, bounded memory.
  `encryptFile` and `decryptFile` publish their output only after full
  verification.
- **Signatures**: ML-DSA-44/65/87 (FIPS 204) and SLH-DSA-SHAKE (FIPS 205)
  with context strings. Also detached signatures, signed artifacts, signed
  manifests, stream and file signing, and `TrustStore` for trust decisions.
- **Hybrid key establishment** with X-Wing and transcript binding.
- **Keys**:
  - Seed-form private keys, `KeyId` fingerprints and lifecycle metadata.
  - Package key records, SPKI and PKCS#8 DER/PEM, interoperable with
    OpenSSL 3.5+.
  - Argon2id-protected exports and password changes.
  - `KeyStore` with rotation, revocation and encrypted backup and restore,
    on `InMemoryKeyStorage` or `FileKeyStorage`.
- **Password-based data encryption** with Argon2id.
- **`SecurityPolicy`**: allowed and minimum algorithms, hybrid-only mode,
  resource limits, Argon2id bounds, and key expiry, revocation and usage
  enforcement.
- **Swappable `CryptoBackend`**: providers for pqcrypto, package:cryptography
  and PointyCastle.
- **`runInBackground`**: runs work in an isolate on native platforms.
- **Formats**: documented in `doc/FORMATS.md`. All are versioned and strictly
  parsed.
- **Tests**:
  - NIST ACVP (ML-KEM, ML-DSA), Wycheproof, X-Wing draft, HPKE-PQ draft and
    RFC vectors.
  - OpenSSL interoperability, parser fuzzing, and browser tests on dart2js
    and dart2wasm.
- **Benchmarks**: `benchmark/main.dart`, with results in `doc/BENCHMARKS.md`.
