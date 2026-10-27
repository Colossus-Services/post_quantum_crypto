# post_quantum_crypto

[![pub package](https://img.shields.io/pub/v/post_quantum_crypto.svg?logo=dart&logoColor=00b9fc)](https://pub.dev/packages/post_quantum_crypto)
[![Null Safety](https://img.shields.io/badge/null-safety-brightgreen)](https://dart.dev/null-safety)
[![Dart CI](https://github.com/Colossus-Services/post_quantum_crypto/actions/workflows/dart.yml/badge.svg?branch=main)](https://github.com/Colossus-Services/post_quantum_crypto/actions/workflows/dart.yml)
[![codecov](https://codecov.io/gh/Colossus-Services/post_quantum_crypto/branch/main/graph/badge.svg)](https://codecov.io/gh/Colossus-Services/post_quantum_crypto)
[![GitHub Tag](https://img.shields.io/github/v/tag/Colossus-Services/post_quantum_crypto?logo=git&logoColor=white)](https://github.com/Colossus-Services/post_quantum_crypto/releases)
[![Last Commits](https://img.shields.io/github/last-commit/Colossus-Services/post_quantum_crypto?logo=git&logoColor=white)](https://github.com/Colossus-Services/post_quantum_crypto/commits/main)
[![License](https://img.shields.io/github/license/Colossus-Services/post_quantum_crypto?logo=open-source-initiative&logoColor=green)](https://github.com/Colossus-Services/post_quantum_crypto/blob/main/LICENSE)

**High-level post-quantum cryptography for Dart and Flutter**, in pure Dart:

- **Encryption**: ML-KEM-768 (FIPS 203) envelopes, with key wrapping by HPKE
  (RFC 9180) and AES-256-GCM, for one or many recipients, one-shot or
  streaming (bounded memory, publish-after-verify file decryption).
- **Signatures**: ML-DSA-65 (FIPS 204), optional SLH-DSA (FIPS 205),
  detached signatures, signed artifacts and signed manifests.
- **Hybrid**: X-Wing (ML-KEM-768 + X25519) recipients and key establishment.
- **Keys**: seed-form keys, fingerprints, lifecycle metadata, SPKI/PKCS#8
  (OpenSSL-compatible), Argon2id-protected exports, key stores, rotation.
- **Policies**: allowed algorithms, minimum security category, hybrid-only,
  size limits, expiry/revocation/usage enforcement.

Runs on the **Dart VM, Flutter (mobile/desktop), JavaScript and
WebAssembly** with no native libraries.

> ⚠️ **No independent security review has been performed yet.** Algorithms
> are checked against official test vectors and against OpenSSL, but that is
> not a design audit. Read [doc/SECURITY.md](doc/SECURITY.md) before relying
> on this package.

## API Documentation

See the [API Documentation][api_doc] for the full list of classes and APIs.

[api_doc]: https://pub.dev/documentation/post_quantum_crypto/latest/

Runnable examples (`dart run example/<name>.dart`):

- [`post_quantum_crypto_example.dart`](example/post_quantum_crypto_example.dart):
  quick tour (encryption, signatures, trust, PEM, X-Wing key establishment).
- [`sharing_and_releases.dart`](example/sharing_and_releases.dart): sharing
  with a changing group (add/remove recipients), authenticated context,
  password-based encryption, streaming with progress, signed release
  manifests and signed artifacts.
- [`key_management.dart`](example/key_management.dart): key metadata,
  rotation, revocation, security policies, encrypted backup and restore,
  PEM export.
- [`file_encryption.dart`](example/file_encryption.dart): streaming file
  encryption, a file-backed key store and password-protected key export.

## Installation

```sh
dart pub add post_quantum_crypto
```

```dart
import 'package:post_quantum_crypto/post_quantum_crypto.dart';
// File helpers (VM / Flutter native only):
import 'package:post_quantum_crypto/post_quantum_crypto_io.dart';
```

## Quick start

```dart
final engine = PostQuantumCryptoEngine();

// Encryption keys (ML-KEM-768 by default).
final recipient = engine.generateEncryptionKeyPair();

final envelope = engine.encrypt(
  utf8.encode('hello, post-quantum world'),
  recipients: [recipient.publicKey],
);
final bytes = envelope.toBytes(); // store or send

final plaintext = engine.decryptBytes(bytes, privateKey: recipient.privateKey);

// Signatures (ML-DSA-65 by default).
final signer = engine.generateSigningKeyPair();
final signature = engine.sign(plaintext, privateKey: signer.privateKey);
final ok = engine.verify(
  plaintext,
  signature: signature,
  publicKey: signer.publicKey,
);
```

`PostQuantumCrypto.encrypt(...)`, `PostQuantumCrypto.sign(...)` etc. are static
shortcuts to a default engine.

**All operations are synchronous and CPU-bound** (microseconds to
milliseconds; Argon2id up to seconds). In a Flutter UI isolate, wrap heavy
calls in `runInBackground`, which uses `Isolate.run` on native platforms and
runs inline on the web, where there are no isolates:

```dart
final keys = await runInBackground(engine.generateSigningKeyPair);
```

## Encryption

### Authenticated context

Bind an envelope to where it is meant to be used. The context is
authenticated but **not encrypted** and is not proof of who encrypted it.

```dart
final env = engine.encrypt(
  data,
  recipients: [recipient.publicKey],
  context: {'tenant': 'acme', 'record': 'invoice-42'},
);

engine.decrypt(
  env,
  privateKey: recipient.privateKey,
  requiredContext: {'tenant': 'acme', 'record': 'invoice-42'},
); // ContextMismatchException if moved to another record
```

### Multiple recipients

The payload is encrypted once; every recipient gets its own encapsulation and
wrapped key. Recipient entries are authenticated, and duplicates are rejected.

```dart
final env = engine.encrypt(
  data,
  recipients: [alice.publicKey, bob.publicKey, hybridCarol.publicKey],
);

// Re-encrypt for a new recipient set (fresh data key):
final updated = engine.addRecipients(
  env,
  privateKey: alice.privateKey,
  currentRecipients: [alice.publicKey, bob.publicKey, hybridCarol.publicKey],
  newRecipients: [dave.publicKey],
);
```

Removing a recipient produces a new envelope; it cannot revoke what that
recipient already decrypted or copied.

### Streams and files

```dart
// Streams: bounded memory (about two chunks).
final encrypted = engine.encryptStream(
  File('big.iso').openRead(),
  recipients: [recipient.publicKey],
  chunkSize: 64 * 1024,
  onProgress: (bytes) => print(bytes),
  cancel: token,
);

// Files: decryptFile writes to a temporary file and renames it into place only
// after the final chunk is authenticated.
await engine.encryptFile('in.bin', 'in.bin.qc', recipients: [recipient.publicKey]);
await engine.decryptFile('in.bin.qc', 'out.bin', privateKey: recipient.privateKey);
```

Streams detect tampering, reordering, duplication, truncation and appended
data. `decryptStream` emits each chunk once it authenticates, so treat output
as unverified until the stream completes without error.

### Algorithm choice

```dart
engine.generateEncryptionKeyPair(algorithm: KemAlgorithm.mlKem1024);
engine.generateEncryptionKeyPair(algorithm: KemAlgorithm.xWing); // hybrid
engine.encrypt(data, recipients: [...], aead: AeadAlgorithm.chacha20Poly1305);
```

## Signatures

```dart
// Standard FIPS 204 signature with a context string (interoperable).
final sig = engine.sign(msg, privateKey: sk, context: utf8.encode('app/v1'));

// Detached signature over content + metadata (also streams/files).
final detached = engine.signDetached(
  content,
  privateKey: sk,
  metadata: {'name': 'app.tar.gz'},
);
final verified = engine.verifyDetached(
  content,
  signature: detached,
  publicKey: pk,
);

// Signed manifest of many files.
final manifest = engine.createSignedManifest([
  await engine.manifestEntryForFile(dir, 'bin/app'),
  await engine.manifestEntryForFile(dir, 'README.md'),
], privateKey: sk);
await engine.verifyManifestFiles(manifest, dir, publicKey: pk);
```

**Verification is not trust.** A valid signature shows that the holder of
that key signed the bytes. Decide separately whether that key is a trusted,
current signer:

```dart
final trust = TrustStore([releaseKey]);
final key = trust.lookup(detached.signerKeyId);
if (key == null) throw 'unknown signer';
final v = engine.verifyDetached(content, signature: detached, publicKey: key);
assert(trust.evaluate(v) == TrustDecision.trusted);
```

SLH-DSA (`SignatureAlgorithm.slhDsaShake128f`, etc.) is available for
hash-based signatures; the `s` sets sign slowly in pure Dart.

## Hybrid key establishment (X-Wing)

```dart
final server = engine.generateEncryptionKeyPair(algorithm: KemAlgorithm.xWing);
const t = HybridTranscript(
  protocol: 'myapp/sync/v1',
  initiatorId: 'client-7',
  responderId: 'server-1',
);

final init = engine.establishHybridKey(server.publicKey, transcript: t);
// send init.message ...
final key = engine.acceptHybridKey(
  init.message,
  privateKey: server.privateKey,
  transcript: t,
);
// key == init.sessionKey
```

The key stays secret if either ML-KEM-768 or X25519 is unbroken. Non-hybrid
KEMs are rejected, which prevents downgrades. **This is not TLS and not
authenticated**: obtain the responder's public key through a trusted channel.

## Keys

```dart
// Raw standard encodings and seeds.
final pk = engine.importEncryptionPublicKey(bytes);
final sk = engine.importEncryptionPrivateKeySeed(seed64);

// X.509 SPKI / PKCS#8 (seed, expanded or both): compatible with OpenSSL 3.5+.
final pem = engine.exportPublicKeyPem(signer.publicKey);
final priv = engine.importPrivateKeyPem(File('key.pem').readAsStringSync());

// Package key record (keeps metadata: created, expires, usages, label, ...).
final record = engine.encodeKey(recipient.publicKey);
final again = engine.decodeEncryptionPublicKey(record);

// Fingerprint for display.
print(recipient.keyId.fingerprint); // e.g. f29b:f240:bb26:...
```

### Password-protected keys

Argon2id (default 64 MiB, 3 passes) with AES-256-GCM, a fresh salt and nonce
each time, and parameter bounds checked before any memory is allocated:

```dart
final blob = engine.exportPrivateKeyWithPassword(sk, 'correct horse battery');
final restored = engine.importPrivateKeyWithPassword(blob, 'correct horse battery');
final rotated = engine.changeKeyPassword(
  blob,
  oldPassword: 'correct horse battery',
  newPassword: 'new passphrase',
);
```

`encryptWithPassword` and `decryptWithPassword` encrypt application data
under a password. That is symmetric encryption, as strong as the password,
and is not post-quantum public-key encryption.

### Key store, rotation, backup

```dart
final store = KeyStore(
  engine,
  FileKeyStorage(Directory('keys')), // or InMemoryKeyStorage, or your own
  password: 'store passphrase',      // encrypts private keys at rest
);
await store.putPair(keys);
final next = await store.rotateEncryptionKey(keys.keyId); // old key: decrypt-only
await store.revoke(oldSigningKeyId, reason: 'compromised');
final backup = await store.backup('backup passphrase');
```

Implement `KeyStorage` to use platform secure storage (Keychain, Android
Keystore, DPAPI, a KMS). `FileKeyStorage` is not hardware-backed.

## Security policies

```dart
final engine = PostQuantumCryptoEngine(
  policy: SecurityPolicy(
    minimumSecurityCategory: 3,              // no ML-KEM-512 / ML-DSA-44
    requireHybridKem: true,                  // X-Wing only
    allowedAeads: {AeadAlgorithm.aes256Gcm},
    limits: ResourceLimits(maxEnvelopePayloadBytes: 16 << 20),
    password: PasswordPolicy(minMemoryKiB: 64 * 1024),
  ),
);
```

Prohibited algorithms are rejected before any expensive work. Expired,
revoked or usage-restricted keys are refused by default.

## Errors

Every error is a `PostQuantumCryptoException`: `InvalidInputException`,
`MalformedDataException`, `UnsupportedAlgorithmException`,
`UnsupportedFormatException`, `InvalidKeyException`,
`DecryptionFailedException`, `SignatureVerificationException`,
`SecureRandomUnavailableException`, `UnsupportedPlatformException`,
`ResourceLimitExceededException`, `PolicyViolationException`,
`KeyNotFoundException`, `ContextMismatchException` and
`OperationCancelledException`. After parsing, every authentication failure
is the same `DecryptionFailedException`, so errors cannot be used as an
oracle. Messages never contain key material.

Two kinds of error pass through unchanged: I/O errors from the file APIs
(`encryptFile`, `decryptFile`, `signFile`, `FileKeyStorage`, …) surface as
`FileSystemException`, and an error raised by a caller-supplied input
stream reaches the caller of `encryptStream`/`decryptStream` as is.

## Architecture: swappable backends

The library depends only on package-owned interfaces (`KemPrimitive`,
`SignaturePrimitive`, `AeadCipher`, `Kdf`, `HashFunction`, `X25519Primitive`,
`Argon2idPrimitive`, ...). The third-party libraries live in single adapter
files under `lib/src/providers/`:

| Provider | Library | Primitives |
|---|---|---|
| `PqcryptoProvider`, `PqcryptoKeccak` | [pqcrypto] | ML-KEM, ML-DSA, SLH-DSA, SHA-3/SHAKE |
| `CryptographyAesGcm`, `CryptographyChaCha20Poly1305`, `CryptographySha2`, `CryptographyX25519` | [cryptography] | AES-GCM, ChaCha20-Poly1305, SHA-2, X25519 |
| `PointyCastleSymmetricProvider` | [pointycastle] | HMAC, HKDF, Argon2id (and alternative AES-GCM/SHA-2/ChaCha) |

To swap a library, for example a native AES or a platform keystore, write a
provider and build a `CryptoBackend`:

```dart
final engine = PostQuantumCryptoEngine(
  backend: standardCryptoBackend.copyWith(symmetric: MyNativeSymmetricProvider()),
);
```

The known-answer suite in `test/vectors/` runs against the configured
providers; a replacement should pass it unchanged.

[pqcrypto]: https://pub.dev/packages/pqcrypto
[cryptography]: https://pub.dev/packages/cryptography
[pointycastle]: https://pub.dev/packages/pointycastle

## Supported platforms

| Platform | Status |
|---|---|
| Dart VM (Linux, macOS, Windows) | ✔ full suite (CI) |
| Flutter Android / iOS / desktop | ✔ pure Dart, same code as the VM (not separately CI-tested) |
| Web, dart2js | ✔ `test/browser` in Chrome (CI) |
| Web, dart2wasm | ✔ `test/browser` in Chrome (CI) |
| `post_quantum_crypto_io.dart` (files, `FileKeyStorage`) | VM / Flutter native only |
| `runInBackground` | real isolate on native; inline on the web |

Secure randomness is `Random.secure()` (OS CSPRNG on native,
`crypto.getRandomValues` in browsers). If it is unavailable, operations fail
with `SecureRandomUnavailableException`; there is no fallback.

## Performance

Pure Dart. On an Apple M-series machine (AOT): ML-KEM-768 envelope
encrypt/decrypt about 0.9 ms; ML-DSA-65 sign 3.2 ms, verify 1.0 ms;
AES-256-GCM about 20 MiB/s; streaming files at about 19 MiB/s, with memory
bounded independent of file size. JavaScript and WebAssembly are 1–3× slower
for the PQ operations, and Argon2id is much slower on the web. Full table:
[doc/BENCHMARKS.md](doc/BENCHMARKS.md).

## Formats and interoperability

- [doc/FORMATS.md](doc/FORMATS.md) specifies every binary format. All are
  versioned (`PQCR` + version + type), strictly parsed and bounded.
- **Standard and interoperable:** FIPS 203/204/205 raw keys and signatures,
  SPKI/PKCS#8 DER/PEM (tested against OpenSSL 3.6), and HPKE key wrapping
  (verified with draft-ietf-hpke-pq vectors).
- **Package-specific:** envelope, stream, signed-object, key-record and
  password containers.
- Test vectors and their provenance are in [test/vectors](test/vectors).

## Security

What is and isn't protected, assumptions and limitations (side channels,
memory erasure, storage, review status): **[doc/SECURITY.md](doc/SECURITY.md)**.

In short:

- **Confidentiality** (encryption) is not **authentication** (who sent it).
  **Signatures** prove possession of a key; **trust** in that key is a
  separate decision.
- Post-quantum algorithms do not protect against compromised endpoints,
  stolen keys, malicious applications or implementation side channels.
- No constant-time guarantee is claimed on any Dart platform.

## Related packages

- [pqcrypto] provides the post-quantum primitives used here.
- [pqforge](https://pub.dev/packages/pqforge) is a different application
  layer over pqcrypto. Its formats are not compatible with this package's.

## Author

Graciliano M. Passos: [gmpassos@GitHub][github].

[github]: https://github.com/gmpassos

## License

[Apache License - Version 2.0][apache_license]

[apache_license]: https://www.apache.org/licenses/LICENSE-2.0.txt
