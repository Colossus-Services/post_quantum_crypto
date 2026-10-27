/// Package-owned interfaces for every cryptographic primitive.
///
/// The rest of the package depends only on these interfaces; the concrete
/// third-party libraries (pqcrypto, PointyCastle, package:cryptography) are
/// confined to the adapter files next to this one. Replacing a dependency
/// means writing a new adapter and plugging it into a [CryptoBackend]. The
/// known-answer test suite runs against whichever backend is configured.
library;

import 'dart:typed_data';

import '../algorithms/algorithms.dart';

export '../encoding/bytes.dart' show Bytes;

/// A key pair as raw byte strings.
typedef RawKeyPair = ({Uint8List publicKey, Uint8List secretKey});

/// The result of a KEM encapsulation.
typedef RawEncapsulation = ({Uint8List ciphertext, Uint8List sharedSecret});

/// An incremental hash computation.
abstract interface class HashSink {
  void add(List<int> data);

  /// Finishes the computation and returns the digest. The sink must not be
  /// used afterwards.
  Uint8List close();
}

/// A cryptographic hash function.
abstract interface class HashFunction {
  HashAlgorithm get algorithm;

  Uint8List hash(List<int> data);

  HashSink start();
}

/// HMAC over a [HashFunction].
abstract interface class MacFunction {
  int get length;

  Uint8List compute(Uint8List key, List<int> data);
}

/// HKDF (RFC 5869) split into its two steps, as HPKE requires.
abstract interface class Kdf {
  KdfAlgorithm get algorithm;

  /// `HKDF-Extract(salt, ikm)`; a null or empty [salt] means `hashLength`
  /// zero bytes.
  Uint8List extract(Uint8List? salt, Uint8List ikm);

  /// `HKDF-Expand(prk, info, length)`; [length] ≤ 255 × `hashLength`.
  Uint8List expand(Uint8List prk, Uint8List info, int length);
}

/// An AEAD cipher with fixed key, nonce and tag lengths.
abstract interface class AeadCipher {
  int get keyLength;

  int get nonceLength;

  int get tagLength;

  /// Encrypts [plaintext] and appends the tag.
  Uint8List seal(
    Uint8List key,
    Uint8List nonce,
    Uint8List plaintext,
    Uint8List aad,
  );

  /// Verifies and decrypts `ciphertext || tag`. Returns `null` when
  /// authentication fails; no plaintext is released in that case.
  Uint8List? open(
    Uint8List key,
    Uint8List nonce,
    Uint8List ciphertextWithTag,
    Uint8List aad,
  );
}

/// A FIPS 203 key-encapsulation mechanism (one parameter set).
abstract interface class KemPrimitive {
  int get publicKeyLength;

  /// Length of the expanded decapsulation key.
  int get secretKeyLength;

  int get ciphertextLength;

  /// `ML-KEM.KeyGen_internal(d, z)` from the 64-byte seed `d || z`.
  RawKeyPair generateFromSeed(Uint8List seed);

  /// `ML-KEM.Encaps_internal(ek, m)` with the 32-byte randomness [m].
  /// Throws when [publicKey] fails the FIPS 203 encapsulation-key check.
  RawEncapsulation encapsulate(Uint8List publicKey, Uint8List m);

  /// `ML-KEM.Decaps(dk, c)`, including implicit rejection: a tampered
  /// ciphertext yields a pseudorandom secret rather than an error.
  Uint8List decapsulate(Uint8List secretKey, Uint8List ciphertext);
}

/// A FIPS 204 / FIPS 205 signature scheme (one parameter set).
abstract interface class SignaturePrimitive {
  int get publicKeyLength;

  int get secretKeyLength;

  int get signatureLength;

  /// Length of the seed accepted by [generateFromSeed], or `null` when the
  /// underlying implementation offers no seeded key generation.
  int? get seedLength;

  /// Deterministic key generation from [seed].
  RawKeyPair generateFromSeed(Uint8List seed);

  /// Key generation using the implementation's own CSPRNG. Only used when
  /// [seedLength] is null.
  RawKeyPair generate();

  /// Pure (non-pre-hashed) signing with FIPS 204/205 context [context]
  /// (≤ 255 bytes) and the hedging randomness [randomness].
  Uint8List sign(
    Uint8List secretKey,
    Uint8List message,
    Uint8List context,
    Uint8List randomness,
  );

  /// Length of the hedging randomness [sign] expects.
  int get randomnessLength;

  /// Returns whether [signature] is valid. Never throws on malformed input.
  bool verify(
    Uint8List publicKey,
    Uint8List message,
    Uint8List signature,
    Uint8List context,
  );
}

/// X25519 (RFC 7748).
abstract interface class X25519Primitive {
  /// `X25519(scalar, 9)`.
  Uint8List publicKey(Uint8List scalar);

  /// `X25519(scalar, point)`.
  Uint8List sharedSecret(Uint8List scalar, Uint8List point);
}

/// SHA-3 / SHAKE (FIPS 202) as used by ML-KEM, ML-DSA and X-Wing.
abstract interface class KeccakPrimitive {
  Uint8List sha3_256(List<int> data);

  Uint8List shake256(List<int> data, int outputLength);
}

/// Argon2id (RFC 9106), version 0x13.
abstract interface class Argon2idPrimitive {
  Uint8List derive({
    required Uint8List password,
    required Uint8List salt,
    required int memoryKiB,
    required int iterations,
    required int parallelism,
    required int length,
    Uint8List? secret,
    Uint8List? associatedData,
  });
}

/// Symmetric primitives (hashes, HMAC, HKDF, AEAD, Argon2id).
abstract interface class SymmetricProvider {
  HashFunction hash(HashAlgorithm algorithm);

  MacFunction hmac(HashAlgorithm algorithm);

  Kdf kdf(KdfAlgorithm algorithm);

  /// The AEAD for [algorithm]. [keyLength] lets internal code request the
  /// AES-128 variant used only by interoperability test vectors.
  AeadCipher aead(AeadAlgorithm algorithm, {int? keyLength});

  Argon2idPrimitive get argon2id;
}

/// Post-quantum primitives (ML-KEM, ML-DSA, SLH-DSA).
abstract interface class PostQuantumProvider {
  /// [algorithm] must be one of the ML-KEM parameter sets.
  KemPrimitive mlKem(KemAlgorithm algorithm);

  SignaturePrimitive signature(SignatureAlgorithm algorithm);
}

/// The set of primitive implementations used by a `QuantumCryptoEngine`.
///
/// `standardCryptoBackend` is the pure-Dart default (pqcrypto, PointyCastle,
/// package:cryptography). A custom backend, for example a native or
/// platform-accelerated one, can be assembled from any combination of
/// providers; it must pass the package's known-answer tests.
final class CryptoBackend {
  final SymmetricProvider symmetric;
  final PostQuantumProvider postQuantum;
  final KeccakPrimitive keccak;
  final X25519Primitive x25519;

  const CryptoBackend({
    required this.symmetric,
    required this.postQuantum,
    required this.keccak,
    required this.x25519,
  });

  /// Returns a copy with some providers replaced.
  CryptoBackend copyWith({
    SymmetricProvider? symmetric,
    PostQuantumProvider? postQuantum,
    KeccakPrimitive? keccak,
    X25519Primitive? x25519,
  }) => CryptoBackend(
    symmetric: symmetric ?? this.symmetric,
    postQuantum: postQuantum ?? this.postQuantum,
    keccak: keccak ?? this.keccak,
    x25519: x25519 ?? this.x25519,
  );
}
