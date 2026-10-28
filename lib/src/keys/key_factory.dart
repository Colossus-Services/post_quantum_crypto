import 'dart:typed_data';

import 'package:meta/meta.dart';

import '../algorithms/algorithms.dart';
import '../context.dart';
import '../encoding/bytes.dart';
import '../errors.dart';
import 'key_metadata.dart';
import 'keys.dart';
import 'ml_dsa_expanded.dart';
import 'slh_dsa_expanded.dart';

/// Key generation and raw import. Internal; reached through the engine.
@internal
final class KeyFactory {
  final CryptoContext _ctx;

  KeyFactory(this._ctx);

  EncryptionKeyPair generateEncryptionKeyPair(
    KemAlgorithm algorithm,
    KeyMetadata metadata,
  ) {
    _ctx.policy.checkKem(algorithm);
    final seed = _ctx.randomBytes(algorithm.seedLength);
    final sk = encryptionPrivateKeyFromSeed(algorithm, seed, metadata);
    return EncryptionKeyPair(sk.publicKey, sk);
  }

  EncryptionPrivateKey encryptionPrivateKeyFromSeed(
    KemAlgorithm algorithm,
    Uint8List seed,
    KeyMetadata metadata,
  ) {
    if (seed.length != algorithm.seedLength) {
      throw InvalidKeyException(
        '${algorithm.standardName} seed must be '
        '${algorithm.seedLength} bytes',
      );
    }
    final ownSeed = Uint8List.fromList(seed);
    final material = _ctx.kem(algorithm).deriveFromSeed(ownSeed);
    final pk = EncryptionPublicKey.internal(
      algorithm: algorithm,
      bytes: material.publicKey,
      keyId: _ctx.encryptionKeyId(algorithm, material.publicKey),
      metadata: metadata,
    );
    return EncryptionPrivateKey.internal(
      publicKey: pk,
      seed: ownSeed,
      secret: material.secret,
    );
  }

  /// Imports an ML-KEM expanded decapsulation key (FIPS 203 `dk`). The
  /// embedded encapsulation key and its hash are validated.
  EncryptionPrivateKey encryptionPrivateKeyFromExpanded(
    KemAlgorithm algorithm,
    Uint8List expanded,
    KeyMetadata metadata,
  ) {
    final material = _ctx.kem(algorithm).fromExpandedSecretKey(expanded);
    final pk = EncryptionPublicKey.internal(
      algorithm: algorithm,
      bytes: material.publicKey,
      keyId: _ctx.encryptionKeyId(algorithm, material.publicKey),
      metadata: metadata,
    );
    return EncryptionPrivateKey.internal(
      publicKey: pk,
      seed: null,
      secret: material.secret,
    );
  }

  EncryptionPublicKey encryptionPublicKey(
    KemAlgorithm algorithm,
    List<int> bytes,
    KeyMetadata metadata,
  ) {
    if (bytes.length != algorithm.publicKeyLength) {
      throw InvalidKeyException(
        '${algorithm.standardName} public key must be '
        '${algorithm.publicKeyLength} bytes',
      );
    }
    final b = Uint8List.fromList(bytes);
    // FIPS 203 encapsulation-key check up front (no encapsulation needed).
    _ctx.kem(algorithm).validatePublicKey(b);
    return EncryptionPublicKey.internal(
      algorithm: algorithm,
      bytes: b,
      keyId: _ctx.encryptionKeyId(algorithm, b),
      metadata: metadata,
    );
  }

  SigningKeyPair generateSigningKeyPair(
    SignatureAlgorithm algorithm,
    KeyMetadata metadata,
  ) {
    _ctx.policy.checkSignature(algorithm);
    final prim = _ctx.signature(algorithm);
    final seedLength = prim.seedLength;
    final SigningPrivateKey sk;
    if (seedLength != null) {
      sk = signingPrivateKeyFromSeed(
        algorithm,
        _ctx.randomBytes(seedLength),
        metadata,
      );
    } else {
      final kp = prim.generate();
      sk = _signingKey(algorithm, null, kp.secretKey, kp.publicKey, metadata);
    }
    return SigningKeyPair(sk.publicKey, sk);
  }

  SigningPrivateKey signingPrivateKeyFromSeed(
    SignatureAlgorithm algorithm,
    Uint8List seed,
    KeyMetadata metadata,
  ) {
    final prim = _ctx.signature(algorithm);
    if (prim.seedLength == null) {
      // SLH-DSA: the canonical private form is the full secret key.
      return signingPrivateKeyFromExpanded(algorithm, seed, null, metadata);
    }
    if (seed.length != prim.seedLength) {
      throw InvalidKeyException(
        '${algorithm.standardName} seed must be ${prim.seedLength} bytes',
      );
    }
    final ownSeed = Uint8List.fromList(seed);
    final kp = prim.generateFromSeed(ownSeed);
    return _signingKey(
      algorithm,
      ownSeed,
      kp.secretKey,
      kp.publicKey,
      metadata,
    );
  }

  /// Imports an expanded signing secret key. For ML-DSA the public key is
  /// recomputed from the secret key (which also checks s1, s2 and t0, see
  /// ml_dsa_expanded.dart) and must match `tr = H(pk)` and [publicKey] when
  /// given. For SLH-DSA, `PK.root` is recomputed from `SK.seed` and
  /// `PK.seed` (slh_dsa_expanded.dart) and must match the secret key and
  /// [publicKey] when given.
  SigningPrivateKey signingPrivateKeyFromExpanded(
    SignatureAlgorithm algorithm,
    Uint8List secretKey,
    List<int>? publicKey,
    KeyMetadata metadata,
  ) {
    final prim = _ctx.signature(algorithm);
    if (secretKey.length != prim.secretKeyLength) {
      throw const InvalidKeyException('Signing secret key has wrong length');
    }
    final Uint8List pk;
    if (algorithm.isSlhDsa) {
      // Recomputes PK.root, so an inconsistent key is rejected.
      pk = slhDsaPublicKeyFromSecretKey(algorithm, secretKey);
      if (publicKey != null && !constantTimeEquals(pk, publicKey)) {
        throw const InvalidKeyException('Public key does not match');
      }
    } else {
      pk = mlDsaPublicKeyFromExpanded(algorithm, secretKey);
      // sk = rho(32) || K(32) || tr(64) || ...; tr = H(pk).
      final tr = _ctx.backend.keccak.shake256(pk, 64);
      if (!constantTimeEquals(secretKey.sublist(64, 128), tr) ||
          (publicKey != null && !constantTimeEquals(pk, publicKey))) {
        throw const InvalidKeyException('Public key does not match');
      }
    }
    return _signingKey(
      algorithm,
      null,
      Uint8List.fromList(secretKey),
      pk,
      metadata,
    );
  }

  SigningPublicKey signingPublicKey(
    SignatureAlgorithm algorithm,
    List<int> bytes,
    KeyMetadata metadata,
  ) {
    if (bytes.length != algorithm.publicKeyLength) {
      throw InvalidKeyException(
        '${algorithm.standardName} public key must be '
        '${algorithm.publicKeyLength} bytes',
      );
    }
    return SigningPublicKey.internal(
      algorithm: algorithm,
      bytes: bytes,
      keyId: _ctx.signingKeyId(algorithm, bytes),
      metadata: metadata,
    );
  }

  SigningPrivateKey _signingKey(
    SignatureAlgorithm algorithm,
    Uint8List? seed,
    Uint8List secretKey,
    Uint8List publicKey,
    KeyMetadata metadata,
  ) {
    final pk = SigningPublicKey.internal(
      algorithm: algorithm,
      bytes: publicKey,
      keyId: _ctx.signingKeyId(algorithm, publicKey),
      metadata: metadata,
    );
    return SigningPrivateKey.internal(
      publicKey: pk,
      seed: seed,
      secretKey: secretKey,
    );
  }
}
