## 2.2.1

### Security

- **A leading U+FEFF no longer collapses map entries.** Dart's
  `utf8.decode` drops a leading byte-order mark (`EF BB BF`), so the
  canonical-map keys `a` and `U+FEFF a` both decoded to `a`. The second
  entry silently overrode the first:
  - in an authenticated context, `{..., 'tenant': 'A', 'U+FEFF tenant': 'B'}`
    parsed as `tenant: B` and passed `requiredContext: {'tenant': 'B'}`;
  - signed metadata was affected the same way;
  - two manifest paths could read as the same path.

  Canonical maps, manifest paths and key metadata now decode losslessly
  (`utf8String`, the inverse of `utf8Bytes`), in linear time however many
  BOMs a value holds.
- **Raw signatures and signed objects are separated.** A detached
  signature or manifest is a signature over
  `post_quantum_crypto/v1/<kind>\0 || body` under the caller's FIPS
  context. A raw signature over a message with that prefix was therefore
  also a valid signed object. A service that raw-signed messages chosen by
  others with its release key could be made to sign content it never saw.
  - Raw `sign` now throws `InvalidInputException` for such messages.
  - Raw `verify` now returns `false` for them, so a published signed object
    no longer verifies as a raw signature.
  - SECURITY.md notes that the guard does not cover the same key raw-signing
    in other implementations.
- **`FileKeyStorage` stages key files privately.** Before, a new temporary
  key file existed with the umask's permissions (typically 0644) until it
  was restricted. Another local user who opened it in that window kept read
  access to the key bytes written afterwards.
  - Key files are now written in an owner-only staging directory,
    `.pending` (`chmod 700`, its mode checked on every write), and renamed
    into place.
  - The permissions of the storage directory itself are left as the caller
    set them.
  - `chmod` is given absolute paths, so a relative directory starting with
    `-` is not read as an option.

### Fixed

- Private-key copies are wiped:
  - `KeyStore` revocation, rotation and restore destroy the private keys
    they load, including on a restore that fails partway;
  - key generation wipes its seed;
  - raw private-key imports wipe their temporary copy of the caller's bytes;
  - signing wipes its hedging randomness.
- The `KeyStore`'s own operations no longer pay the SLH-DSA key check (1–2 s
  per "s" key) for keys they only carry over. This covers revocation,
  rotation, backup and restore, and `changeKeyPassword` does the same. A key
  is still checked when it is loaded for use with `get`.
- `verifySlhDsaKey: false` is also honoured for an SLH-DSA key record in
  seed form.
- `importSigningPrivateKeyExpanded` documents the SLH-DSA check and its
  cost.
- Raw and signed-object signing share one implementation.

### Tests

- Regression tests for each fix (`test/unit/review_regressions_test.dart`):
  - U+FEFF-prefixed context keys, signed metadata, manifest paths and key
    labels, and a 64 KiB value made only of BOMs;
  - raw signing and verification of signed-object domains, and near misses
    that still sign;
  - wiping of key-generation seeds and signing randomness, through a spying
    random source;
  - key-store revoke, rotate and restore leaving usable keys, and a backup
    with a bad record restoring nothing;
  - the opt-out for seed-form SLH-DSA records;
  - `FileKeyStorage` staging, checked on POSIX and run on Linux, macOS and
    Windows.

  Seven of them fail without the fixes.

### Documentation

- `test/README.md` describes each test directory, the tags and the NIST
  ACVP vectors: which files, parameter sets and subsets, and what each test
  checks.

## 2.2.0

### Fixed

- **SLH-DSA private keys are checked on import.** `PK.root` is recomputed
  from `SK.seed` and `PK.seed` (FIPS 205 Algorithm 18) and must match.
  Before, a corrupted or inconsistent key (PKCS#8, raw bytes, key record)
  imported silently and then produced only signatures that fail
  verification. This closes the last limitation on private-key import
  listed in SECURITY.md.
  - Cost: one key generation per import and per key-store load. That is
    milliseconds for the "f" parameter sets and 1–2 s for the "s" sets.
  - Loading a key record can skip it: `decodeKey`,
    `decodeSigningPrivateKey`, `importPrivateKeyWithPassword` and
    `KeyStore.get` take `verifySlhDsaKey` (default `true`). PKCS#8 and raw
    imports are always checked.
- **SLH-DSA key generation uses the package's random source.** It used
  pqcrypto's own `Random.secure()`, so a random source configured on the
  engine was ignored for it. All randomness now comes from the package.
  This closes the SLH-DSA key-generation limitation in SECURITY.md.

### Changed

- **pqcrypto: ^0.4.4**, which exports FIPS 205 Algorithm 18
  (`SlhDsa.generateKeyPairSeeded`,
  [turkananation/pqcrypto#69](https://github.com/turkananation/pqcrypto/pull/69)).
- **`SignaturePrimitive`** (custom backends):
  - `generate()` becomes `generate(Uint8List randomness)`, with the new
    `keyGenerationRandomnessLength`. For SLH-DSA the randomness is
    `SK.seed || SK.prf || PK.seed`.
  - New `publicKeyFromSecretKey(secretKey)`, which checks an SLH-DSA
    secret key and returns its public key. The SLH-DSA check now runs in
    the backend, not in a separate file importing pqcrypto.
- Loading a key record compares the stored public key once, not twice.

### Tests

- NIST ACVP SLH-DSA keyGen vectors (SHAKE parameter sets): the official
  secret keys pass the check and yield the official public keys without
  being given them, and key generation from the official seeds reproduces
  the official key pair.
- Mutation tests for SLH-DSA (128f/192f/256f):
  - `SK.seed`, `PK.seed` and `PK.root` changes are rejected, via raw and
    PKCS#8 import;
  - `SK.prf`, which FIPS 205 leaves unconstrained, is accepted and still
    signs;
  - with `verifySlhDsaKey: false` a corrupted key record loads (and its
    signatures fail), while the stored public key is still compared.
- SLH-DSA-SHAKE-128s: a `PK.root` change is rejected (tagged `slow`).
- SLH-DSA key generation is deterministic under a deterministic random
  source.

## 2.1.1

### Documentation

README brought up to date with 2.1.0:

- Key import validation: expanded keys are checked for consistency, and an
  expanded-only ML-DSA key imports on its own.
- Supported platforms: macOS and Windows run the platform-sensitive tests in
  CI, Linux runs the full suite.
- Architecture: the ML-DSA key check uses pqcrypto's SHAKE128 directly.
- The third-party test vectors are in the repository, not in the package.

No code changes.

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
  required alongside. `importSigningPrivateKeyExpanded`'s `publicKey` is
  now optional; when given, it must match the recomputed one.
- The new key checks evaluate every coefficient before deciding (timing does
  not depend on where a key fails) and wipe every buffer derived from the
  secret key, including a rejected key's copy. They cost about one signing
  operation per import (ML-DSA-87: ~6 ms on the VM).

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
  - The VM suite runs in four coverage shards of similar length (the
    `vectors` tag and the rest, each split in two); Codecov waits for all
    uploads. The
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
