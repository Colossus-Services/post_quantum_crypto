import 'dart:typed_data';

import 'package:meta/meta.dart';

import '../algorithms/algorithms.dart';
import '../encoding/bytes.dart';
import '../errors.dart';
import '../kem/kem_scheme.dart';
import 'key_metadata.dart';

/// Any key handled by this package: [EncryptionPublicKey],
/// [EncryptionPrivateKey], [SigningPublicKey] or [SigningPrivateKey].
sealed class QuantumKey {
  KeyId get keyId;

  KeyMetadata get metadata;

  /// Whether this is a private key.
  bool get isPrivate;
}

/// A public encryption (KEM) key. Immutable.
///
/// Obtain one from `PostQuantumCryptoEngine.generateEncryptionKeyPair` or one of
/// the engine's import methods.
final class EncryptionPublicKey implements QuantumKey {
  @override
  bool get isPrivate => false;

  final KemAlgorithm algorithm;

  /// The standardized public-key encoding (FIPS 203 `ek`; for X-Wing,
  /// `ek_ML-KEM || X25519 public key`). Unmodifiable.
  final Bytes bytes;

  @override
  final KeyId keyId;

  @override
  final KeyMetadata metadata;

  @internal
  EncryptionPublicKey.internal({
    required this.algorithm,
    required List<int> bytes,
    required this.keyId,
    this.metadata = const KeyMetadata(),
  }) : bytes = immutableCopy(bytes) {
    metadata.checkLimits();
  }

  /// Returns a copy carrying [metadata].
  EncryptionPublicKey withMetadata(KeyMetadata metadata) =>
      EncryptionPublicKey.internal(
        algorithm: algorithm,
        bytes: bytes,
        keyId: keyId,
        metadata: metadata,
      );

  @override
  bool operator ==(Object other) =>
      other is EncryptionPublicKey &&
      other.algorithm == algorithm &&
      other.keyId == keyId;

  @override
  int get hashCode => Object.hash(algorithm, keyId);

  @override
  String toString() =>
      'EncryptionPublicKey(${algorithm.standardName}, ${keyId.fingerprint})';
}

/// A private encryption (KEM) key.
///
/// Holds the private seed (the canonical private form) and the expanded
/// decapsulation key derived from it. [toString] never prints key material.
/// Call [destroy] to clear the secret buffers when the key is no longer
/// needed (best-effort; see `zeroize`).
final class EncryptionPrivateKey implements QuantumKey {
  @override
  bool get isPrivate => true;

  final EncryptionPublicKey publicKey;
  final Uint8List? _seed;
  final KemSecret _secret;
  bool _destroyed = false;

  @internal
  EncryptionPrivateKey.internal({
    required this.publicKey,
    required Uint8List? seed,
    required KemSecret secret,
  }) : _seed = seed,
       _secret = secret;

  KemAlgorithm get algorithm => publicKey.algorithm;

  @override
  KeyId get keyId => publicKey.keyId;

  @override
  KeyMetadata get metadata => publicKey.metadata;

  /// Whether the private seed is available (keys imported in expanded-only
  /// form have none and cannot be exported in seed form).
  bool get hasSeed => _seed != null;

  bool get isDestroyed => _destroyed;

  @internal
  Uint8List get seed {
    _checkAlive();
    final s = _seed;
    if (s == null) {
      throw const InvalidKeyException('Key has no seed form');
    }
    return s;
  }

  @internal
  KemSecret get secret {
    _checkAlive();
    return _secret;
  }

  /// Returns a copy carrying [metadata]. The copy shares the secret buffers.
  EncryptionPrivateKey withMetadata(KeyMetadata metadata) =>
      EncryptionPrivateKey.internal(
        publicKey: publicKey.withMetadata(metadata),
        seed: _seed,
        secret: _secret,
      );

  void _checkAlive() {
    if (_destroyed) throw const InvalidKeyException('Key was destroyed');
  }

  /// Overwrites the secret material with zeros (best-effort). The key is
  /// unusable afterwards, as is every copy made with [withMetadata].
  void destroy() {
    _destroyed = true;
    zeroize(_seed);
    _secret.destroy();
  }

  @override
  String toString() =>
      'EncryptionPrivateKey(${algorithm.standardName}, '
      '${keyId.fingerprint}, <redacted>)';
}

/// An encryption key pair.
final class EncryptionKeyPair {
  final EncryptionPublicKey publicKey;
  final EncryptionPrivateKey privateKey;

  const EncryptionKeyPair(this.publicKey, this.privateKey);

  KeyId get keyId => publicKey.keyId;
}

/// A public signing key. Immutable.
final class SigningPublicKey implements QuantumKey {
  @override
  bool get isPrivate => false;

  final SignatureAlgorithm algorithm;

  /// The standardized public-key encoding (FIPS 204 / FIPS 205). Unmodifiable.
  final Bytes bytes;

  @override
  final KeyId keyId;

  @override
  final KeyMetadata metadata;

  @internal
  SigningPublicKey.internal({
    required this.algorithm,
    required List<int> bytes,
    required this.keyId,
    this.metadata = const KeyMetadata(),
  }) : bytes = immutableCopy(bytes) {
    metadata.checkLimits();
  }

  SigningPublicKey withMetadata(KeyMetadata metadata) =>
      SigningPublicKey.internal(
        algorithm: algorithm,
        bytes: bytes,
        keyId: keyId,
        metadata: metadata,
      );

  @override
  bool operator ==(Object other) =>
      other is SigningPublicKey &&
      other.algorithm == algorithm &&
      other.keyId == keyId;

  @override
  int get hashCode => Object.hash(algorithm, keyId);

  @override
  String toString() =>
      'SigningPublicKey(${algorithm.standardName}, ${keyId.fingerprint})';
}

/// A private signing key. [toString] never prints key material.
final class SigningPrivateKey implements QuantumKey {
  @override
  bool get isPrivate => true;

  final SigningPublicKey publicKey;
  final Uint8List? _seed;
  final Uint8List _secretKey;
  bool _destroyed = false;

  @internal
  SigningPrivateKey.internal({
    required this.publicKey,
    required Uint8List? seed,
    required Uint8List secretKey,
  }) : _seed = seed,
       _secretKey = secretKey;

  SignatureAlgorithm get algorithm => publicKey.algorithm;

  @override
  KeyId get keyId => publicKey.keyId;

  @override
  KeyMetadata get metadata => publicKey.metadata;

  /// Whether the ML-DSA seed `ξ` is available.
  bool get hasSeed => _seed != null;

  bool get isDestroyed => _destroyed;

  @internal
  Uint8List? get seedOrNull {
    _checkAlive();
    return _seed;
  }

  @internal
  Uint8List get secretKey {
    _checkAlive();
    return _secretKey;
  }

  SigningPrivateKey withMetadata(KeyMetadata metadata) =>
      SigningPrivateKey.internal(
        publicKey: publicKey.withMetadata(metadata),
        seed: _seed,
        secretKey: _secretKey,
      );

  void _checkAlive() {
    if (_destroyed) throw const InvalidKeyException('Key was destroyed');
  }

  /// Overwrites the secret material with zeros (best-effort).
  void destroy() {
    _destroyed = true;
    zeroize(_seed);
    zeroize(_secretKey);
  }

  @override
  String toString() =>
      'SigningPrivateKey(${algorithm.standardName}, '
      '${keyId.fingerprint}, <redacted>)';
}

/// A signing key pair.
final class SigningKeyPair {
  final SigningPublicKey publicKey;
  final SigningPrivateKey privateKey;

  const SigningKeyPair(this.publicKey, this.privateKey);

  KeyId get keyId => publicKey.keyId;
}
