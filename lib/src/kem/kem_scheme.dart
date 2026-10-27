/// KEM schemes in the HPKE KEM interface shape: seed-based key derivation,
/// derandomized encapsulation and decapsulation.
library;

import 'dart:typed_data';

import '../algorithms/algorithms.dart';
import '../encoding/bytes.dart';
import '../errors.dart';
import '../providers/primitives.dart';

/// Expanded private-key material held by an encryption private key.
final class KemSecret {
  final List<Uint8List> _parts;

  KemSecret(this._parts);

  Uint8List part(int i) => _parts[i];

  void destroy() {
    for (final p in _parts) {
      zeroize(p);
    }
  }
}

/// A key pair derived from a seed.
typedef KemKeyMaterial = ({Uint8List publicKey, KemSecret secret});

/// A KEM usable for envelope recipients and hybrid key establishment.
abstract interface class KemScheme {
  KemAlgorithm get algorithm;

  /// Deterministically derives the key pair from the private seed.
  KemKeyMaterial deriveFromSeed(Uint8List seed);

  /// Rebuilds the private material from an expanded secret key (ML-KEM
  /// decapsulation key imported from another implementation).
  KemKeyMaterial fromExpandedSecretKey(Uint8List expanded);

  /// Validates an encapsulation key without encapsulating.
  void validatePublicKey(Uint8List publicKey);

  /// Derandomized encapsulation; [randomness] has
  /// [KemAlgorithm.encapsulationRandomLength] bytes.
  RawEncapsulation encapsulate(Uint8List publicKey, Uint8List randomness);

  Uint8List decapsulate(KemSecret secret, Uint8List ciphertext);
}

/// Returns the [KemScheme] for [algorithm] built on [backend].
KemScheme kemSchemeFor(KemAlgorithm algorithm, CryptoBackend backend) =>
    switch (algorithm) {
      KemAlgorithm.mlKem512 ||
      KemAlgorithm.mlKem768 ||
      KemAlgorithm.mlKem1024 => MlKemScheme(
        algorithm,
        backend.postQuantum.mlKem(algorithm),
        backend.keccak,
      ),
      KemAlgorithm.xWing => XWingScheme(
        backend.postQuantum.mlKem(KemAlgorithm.mlKem768),
        backend.x25519,
        backend.keccak,
      ),
    };

/// ML-KEM (FIPS 203). The private seed is `d || z` (64 bytes), the seed
/// format of draft-ietf-lamps-kyber-certificates and draft-ietf-hpke-pq.
final class MlKemScheme implements KemScheme {
  @override
  final KemAlgorithm algorithm;
  final KemPrimitive _kem;
  final KeccakPrimitive _keccak;

  MlKemScheme(this.algorithm, this._kem, this._keccak);

  @override
  KemKeyMaterial deriveFromSeed(Uint8List seed) {
    if (seed.length != 64) {
      throw const InvalidKeyException('ML-KEM seed must be 64 bytes');
    }
    final kp = _kem.generateFromSeed(seed);
    return (publicKey: kp.publicKey, secret: KemSecret([kp.secretKey]));
  }

  @override
  KemKeyMaterial fromExpandedSecretKey(Uint8List expanded) {
    if (expanded.length != _kem.secretKeyLength) {
      throw const InvalidKeyException('ML-KEM secret key has wrong length');
    }
    // dk = dk_PKE || ek || H(ek) || z; FIPS 203 §7.3 hash check.
    final k = (_kem.publicKeyLength - 32) ~/ 384;
    final ekStart = 384 * k;
    final ekEnd = ekStart + _kem.publicKeyLength;
    final ek = Uint8List.sublistView(expanded, ekStart, ekEnd);
    final h = Uint8List.sublistView(expanded, ekEnd, ekEnd + 32);
    if (!constantTimeEquals(_keccak.sha3_256(ek), h)) {
      throw const InvalidKeyException('ML-KEM secret key fails hash check');
    }
    final material = (
      publicKey: Uint8List.fromList(ek),
      secret: KemSecret([Uint8List.fromList(expanded)]),
    );
    _pairwiseConsistency(material, expanded);
    return material;
  }

  /// Pairwise-consistency test: the hash check above does not cover the
  /// secret vector s, so a key with a mutated s (RFC 9935 C.4.1, example 2)
  /// would otherwise import and then silently fail every decapsulation.
  /// Encapsulates to the embedded public key and requires decapsulation to
  /// agree. The message is derived from the key, so no randomness is needed.
  void _pairwiseConsistency(KemKeyMaterial material, Uint8List expanded) {
    final m = _keccak.sha3_256(expanded);
    final RawEncapsulation encap;
    try {
      encap = encapsulate(material.publicKey, m);
    } finally {
      zeroize(m);
    }
    final ss = decapsulate(material.secret, encap.ciphertext);
    final ok = constantTimeEquals(ss, encap.sharedSecret);
    zeroize(ss);
    zeroize(encap.sharedSecret);
    if (!ok) {
      throw const InvalidKeyException(
        'ML-KEM secret key fails the pairwise consistency test',
      );
    }
  }

  @override
  void validatePublicKey(Uint8List publicKey) =>
      _kem.validatePublicKey(publicKey);

  @override
  RawEncapsulation encapsulate(Uint8List publicKey, Uint8List randomness) {
    if (publicKey.length != algorithm.publicKeyLength) {
      throw const InvalidKeyException('ML-KEM public key has wrong length');
    }
    return _kem.encapsulate(publicKey, randomness);
  }

  @override
  Uint8List decapsulate(KemSecret secret, Uint8List ciphertext) =>
      _kem.decapsulate(secret.part(0), ciphertext);
}

/// X-Wing (draft-connolly-cfrg-xwing-kem-10): ML-KEM-768 ⊕ X25519 with the
/// SHA3-256 combiner. The private key is the 32-byte seed.
final class XWingScheme implements KemScheme {
  static final Uint8List _label = Uint8List.fromList([
    0x5c, 0x2e, 0x2f, 0x2f, 0x5e, 0x5c, // "\./" "/^\"
  ]);

  final KemPrimitive _mlKem;
  final X25519Primitive _x25519;
  final KeccakPrimitive _keccak;

  XWingScheme(this._mlKem, this._x25519, this._keccak);

  @override
  KemAlgorithm get algorithm => KemAlgorithm.xWing;

  @override
  KemKeyMaterial deriveFromSeed(Uint8List seed) {
    if (seed.length != 32) {
      throw const InvalidKeyException('X-Wing seed must be 32 bytes');
    }
    final expanded = _keccak.shake256(seed, 96);
    try {
      final kp = _mlKem.generateFromSeed(
        Uint8List.sublistView(expanded, 0, 64),
      );
      final skX = Uint8List.fromList(Uint8List.sublistView(expanded, 64, 96));
      final pkX = _x25519.publicKey(skX);
      return (
        publicKey: concatBytes([kp.publicKey, pkX]),
        secret: KemSecret([kp.secretKey, skX, pkX]),
      );
    } finally {
      zeroize(expanded);
    }
  }

  @override
  KemKeyMaterial fromExpandedSecretKey(Uint8List expanded) =>
      throw const InvalidKeyException(
        'X-Wing private keys are only exchanged in seed form',
      );

  @override
  void validatePublicKey(Uint8List publicKey) {
    if (publicKey.length != 1216) {
      throw const InvalidKeyException('X-Wing public key has wrong length');
    }
    // Every 32-byte string is a valid X25519 public key.
    _mlKem.validatePublicKey(Uint8List.sublistView(publicKey, 0, 1184));
  }

  @override
  RawEncapsulation encapsulate(Uint8List publicKey, Uint8List randomness) {
    if (publicKey.length != 1216) {
      throw const InvalidKeyException('X-Wing public key has wrong length');
    }
    if (randomness.length != 64) {
      throw const InvalidInputException('X-Wing randomness must be 64 bytes');
    }
    final pkM = Uint8List.sublistView(publicKey, 0, 1184);
    final pkX = Uint8List.sublistView(publicKey, 1184, 1216);
    final ekX = Uint8List.sublistView(randomness, 32, 64);
    final ctX = _x25519.publicKey(ekX);
    final ssX = _x25519.sharedSecret(ekX, pkX);
    final m = _mlKem.encapsulate(pkM, Uint8List.sublistView(randomness, 0, 32));
    try {
      return (
        ciphertext: concatBytes([m.ciphertext, ctX]),
        sharedSecret: _combine(m.sharedSecret, ssX, ctX, pkX),
      );
    } finally {
      zeroize(ssX);
      zeroize(m.sharedSecret);
    }
  }

  @override
  Uint8List decapsulate(KemSecret secret, Uint8List ciphertext) {
    if (ciphertext.length != 1120) {
      throw const MalformedDataException('X-Wing ciphertext has wrong length');
    }
    final ctM = Uint8List.sublistView(ciphertext, 0, 1088);
    final ctX = Uint8List.sublistView(ciphertext, 1088, 1120);
    final ssM = _mlKem.decapsulate(secret.part(0), ctM);
    final ssX = _x25519.sharedSecret(secret.part(1), ctX);
    try {
      return _combine(ssM, ssX, ctX, secret.part(2));
    } finally {
      zeroize(ssM);
      zeroize(ssX);
    }
  }

  Uint8List _combine(
    Uint8List ssM,
    Uint8List ssX,
    Uint8List ctX,
    Uint8List pkX,
  ) {
    final input = concatBytes([ssM, ssX, ctX, pkX, _label]);
    try {
      return _keccak.sha3_256(input);
    } finally {
      zeroize(input);
    }
  }
}
