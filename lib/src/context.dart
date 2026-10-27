import 'dart:typed_data';

import 'package:meta/meta.dart';

import 'algorithms/algorithms.dart';
import 'encoding/bytes.dart';
import 'encoding/canonical.dart';
import 'kem/kem_scheme.dart';
import 'keys/key_metadata.dart';
import 'policy.dart';
import 'providers/primitives.dart';
import 'random/secure_random.dart';

/// Shared state of an engine: backend, policy and randomness. Internal.
@internal
final class CryptoContext {
  final CryptoBackend backend;
  final SecurityPolicy policy;
  final SecureRandomSource random;
  final Map<KemAlgorithm, KemScheme> _kems = {};

  CryptoContext(this.backend, this.policy, this.random);

  Uint8List randomBytes(int length) => random.nextBytes(length);

  /// Hash function for [algorithm] (SHA-3 is served by the Keccak provider).
  HashFunction hash(HashAlgorithm algorithm) =>
      algorithm == HashAlgorithm.sha3_256
      ? _Sha3Hash(backend.keccak)
      : backend.symmetric.hash(algorithm);

  Uint8List sha256(List<int> data) => hash(HashAlgorithm.sha256).hash(data);

  Uint8List sha384(List<int> data) => hash(HashAlgorithm.sha384).hash(data);

  KemScheme kem(KemAlgorithm algorithm) =>
      _kems.putIfAbsent(algorithm, () => kemSchemeFor(algorithm, backend));

  Kdf get hkdfSha384 => backend.symmetric.kdf(KdfAlgorithm.hkdfSha384);

  AeadCipher aead(AeadAlgorithm algorithm) => backend.symmetric.aead(algorithm);

  SignaturePrimitive signature(SignatureAlgorithm algorithm) =>
      backend.postQuantum.signature(algorithm);

  MapLimits get mapLimits => (
    maxEntries: policy.limits.maxContextEntries,
    maxKeyBytes: policy.limits.maxContextKeyBytes,
    maxValueBytes: policy.limits.maxContextValueBytes,
  );

  static final Uint8List _keyIdLabel = utf8Bytes(
    'post_quantum_crypto/v1/key-id',
  );

  KeyId keyId(int kind, int algorithmId, List<int> publicKey) {
    final w = ByteWriter()
      ..raw(_keyIdLabel)
      ..u8(0)
      ..u8(kind)
      ..u16(algorithmId)
      ..raw(publicKey);
    return KeyId(sha256(w.toBytes()));
  }

  KeyId encryptionKeyId(KemAlgorithm a, List<int> publicKey) =>
      keyId(1, a.id, publicKey);

  KeyId signingKeyId(SignatureAlgorithm a, List<int> publicKey) =>
      keyId(2, a.id, publicKey);
}

final class _Sha3Hash implements HashFunction {
  final KeccakPrimitive _k;

  _Sha3Hash(this._k);

  @override
  HashAlgorithm get algorithm => HashAlgorithm.sha3_256;

  @override
  Uint8List hash(List<int> data) => _k.sha3_256(data);

  @override
  HashSink start() => _BufferedSink(this);
}

final class _BufferedSink implements HashSink {
  final HashFunction _h;
  final BytesBuilder _b = BytesBuilder(copy: true);

  _BufferedSink(this._h);

  @override
  void add(List<int> data) => _b.add(data);

  @override
  Uint8List close() => _h.hash(_b.takeBytes());
}
