## 2.1.0

### Fixed

Found by the new standards-conformance vectors (below):

- **ML-DSA expanded private keys with s1 or s2 out of range** were accepted
  and used to sign (Wycheproof). They are now rejected.
- **ML-DSA expanded private keys whose `t0` does not match s1 and s2** were
  accepted, even with the matching public key (RFC 9881 C.4, example 3).
  The import now recomputes `t = A·s1 + s2` (FIPS 204) and rejects them.
- **ML-KEM expanded private keys with a mutated secret vector** but a valid
  `H(ek)` were accepted and then silently failed every decapsulation
  (RFC 9935 C.4.1, example 2). The import now runs a pairwise-consistency
  test.

### Changed

- An **expanded-only ML-DSA private key** (PKCS#8, RFC 9881 `expandedKey`)
  now imports on its own: its public key is recomputed instead of being
  required alongside. `importSigningPrivateKeyExpanded` still takes the
  public key and checks it.

### Tests

- Wycheproof ML-KEM (key generation, encapsulation with unreduced and
  overflowing keys, decapsulation incl. CCTV strcmp, expanded keys) and
  ML-DSA (deterministic and randomized signing, invalid keys, verification
  of malformed signatures) for every parameter set.
- RFC 9881 and RFC 9935 Appendix C: every example key in the seed,
  expanded and both forms is imported and re-exported byte for byte, and
  every inconsistent key is rejected.
- `tool/fetch_vectors.dart` fetches and trims the new sources;
  `test/vectors/PROVENANCE.md` records them. Third-party vectors are no
  longer included in the published package (159 KB instead of 3 MB).

### CI

- Faster CI through parallel jobs:
  - The VM suite runs in two coverage shards of similar length, partitioned
    by tag (`vectors`, and the rest); Codecov waits for both uploads. The
    few `slow` tests run in their own job without coverage instrumentation,
    which slowed them several times over.
  - Lint and package checks are separate jobs, and the examples run
    concurrently.
  - The macOS/Windows jobs run only the tests tagged `platform` (file
    system, permissions, processes, isolates); everything else is pure Dart
    computation and already runs on Linux and in browsers.
  - A newer push to a PR cancels the running check.

## 2.0.1

### Fixed

- **Key labels and revocation reasons are checked where they are
  introduced.** Before, a label over 4096 UTF-8 bytes (or with an unpaired
  surrogate) was only rejected when the key was saved. Now key generation,
  import, `withMetadata` and `KeyMetadata.copyWith` reject it. The new
  `KeyMetadata.checkLimits` does the same check on demand. Behavior
  change: a key with such a label can no longer be created even if it is
  never saved.
- **`KeyStore.backup` no longer fails on a misplaced key file.** Each
  storage entry is decoded on its own and its key is backed up under its
  real id, so a key file moved or copied over another key's name is still
  backed up (once) and restored under the right name. An entry that holds
  no valid key fails the backup as before, unless the new optional
  `onSkipped` callback is given, in which case it is left out and reported
  there. A wrong store password always fails the backup. Decrypted private
  keys are destroyed once encoded.
- **pub.dev:** shorter pubspec `description` (163 characters). pub.dev
  requires 60–180 and scored the package 0/10 for "Provide a valid
  pubspec.yaml".

## 2.0.0

### Breaking

- **Wire format 2.** Every object now carries format version 2, and
  objects written by 1.x (format 1) are rejected with
  `UnsupportedFormatException`; there is no migration path. Keys can still
  be moved over as SPKI/PKCS#8 or raw seeds, and key identifiers are
  unchanged.
- **Key-committing encryption.** Envelopes, streams and password objects
  derive their payload key together with a stored 32-byte commitment,
  checked before the AEAD opens. A malicious sender can no longer make one
  multi-recipient envelope or stream decrypt to different plaintexts for
  different recipients ("invisible salamanders"), and a password object
  opens under at most one password (no partitioning oracles). See
  doc/FORMAT_V2.md.
- Streams no longer carry the 32-byte salt field.
- Strings with unpaired UTF-16 surrogates are rejected everywhere,
  passwords and hybrid transcript identities included.

### Added

- `EncryptedEnvelope.formatVersion` and `StreamHeader.formatVersion`.
- `TrustStore.withClock` and `PostQuantumCryptoEngine.createTrustStore`,
  whose `evaluate` judges expiry by the engine's policy clock.
- "Format evolution" rules in doc/FORMATS.md. Every parser checks the
  format version in one place, so a future format version can keep reading
  this one behind `SecurityPolicy.acceptLegacyFormats`.

### Tests

- A real two-key AES-GCM collision ("invisible salamanders") built with
  GHASH arithmetic, rejected by the commitment.
- Format vectors are now `test/vectors/post_quantum_crypto_v2.json`.

## 1.0.1

### Fixed

- **Key metadata**: a label or revocation reason over 4096 UTF-8 bytes is
  now rejected when written (`ResourceLimitExceededException`). Before, it
  was written but could not be read back, making the stored key
  unrecoverable.
- **Key metadata**: a date beyond `DateTime`'s range in a key record raises
  `MalformedDataException` instead of a raw `RangeError`.
- **Strings with unpaired UTF-16 surrogates** in fields that are decoded
  back (authenticated contexts, signed metadata, key labels and revocation
  reasons, manifest paths) are rejected with `InvalidInputException`.
  Before, they were silently encoded as U+FFFD, so two distinct context keys
  could produce an envelope that no recipient could open, and decoding did
  not reproduce the input. Passwords and hybrid transcript identities are
  only hashed and keep the 1.0.0 encoding, so existing data stays readable.
- **`KeyStore.get`** checks that the stored entry holds the requested key
  (key id, and private vs public); a swapped or misplaced file raises
  `InvalidKeyException` instead of returning a different key.
- **`FileKeyStorage.delete`** waits for pending writes of the same key, so
  a delete issued after a write is no longer undone by that write. An
  invalid key name fails the returned Future instead of throwing
  synchronously.
- **Stream decryption** opens chunks one at a time as they are emitted, so
  a large input event no longer holds all its plaintext at once, and
  `onProgress` reports each chunk as it is emitted instead of a batch total
  ahead of time.

### Documentation

- SECURITY.md: multi-recipient envelopes and streams are not key-committing;
  SLH-DSA private-key import takes the public key from the secret key.
- README: file APIs and caller-supplied input streams let their own errors
  through unchanged.
- `TrustStore.evaluate` and `decryptFile` document their clock and file
  permission behaviour.

### Examples

- New `example/sharing_and_releases.dart` (group sharing with
  add/remove recipients, password-based encryption, streaming progress,
  signed manifests and artifacts) and `example/key_management.dart`
  (metadata, rotation, revocation, policies, backup/restore, PEM). The
  README lists every example, and CI runs them all.

### CI and tests

- Coverage is uploaded to Codecov (`codecov/codecov-action@v7`); README
  shows the Codecov badge. `actions/checkout` upgraded to v7.
- New tests for DER/PKCS#8 of every signature algorithm, PKCS#8 v2
  embedded public keys, stream decryption cancellation and deferred header
  parsing, and the fixes above.

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
