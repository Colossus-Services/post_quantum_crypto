import '../algorithms/algorithms.dart';
import 'cryptography_provider.dart';
import 'pointycastle_provider.dart';
import 'pqcrypto_provider.dart';
import 'primitives.dart';

/// A [SymmetricProvider] that takes the AEADs and SHA-2 from
/// package:cryptography (much faster in pure Dart, and its ChaCha20-Poly1305
/// works on JavaScript) and HMAC, HKDF and Argon2id from PointyCastle.
final class ComposedSymmetricProvider implements SymmetricProvider {
  final SymmetricProvider _base;

  const ComposedSymmetricProvider([
    this._base = const PointyCastleSymmetricProvider(),
  ]);

  @override
  HashFunction hash(HashAlgorithm algorithm) =>
      algorithm == HashAlgorithm.sha3_256
      ? _base.hash(algorithm)
      : CryptographySha2(algorithm);

  @override
  MacFunction hmac(HashAlgorithm algorithm) => _base.hmac(algorithm);

  @override
  Kdf kdf(KdfAlgorithm algorithm) => _base.kdf(algorithm);

  @override
  AeadCipher aead(AeadAlgorithm algorithm, {int? keyLength}) =>
      switch (algorithm) {
        AeadAlgorithm.aes256Gcm => CryptographyAesGcm(keyLength ?? 32),
        AeadAlgorithm.chacha20Poly1305 => const CryptographyChaCha20Poly1305(),
      };

  @override
  Argon2idPrimitive get argon2id => _base.argon2id;
}

/// The default pure-Dart backend:
///
/// - pqcrypto: ML-KEM, ML-DSA, SLH-DSA, SHA-3/SHAKE;
/// - package:cryptography: AES-256-GCM, ChaCha20-Poly1305, SHA-2, X25519;
/// - PointyCastle: HMAC, HKDF, Argon2id.
const CryptoBackend standardCryptoBackend = CryptoBackend(
  symmetric: ComposedSymmetricProvider(),
  postQuantum: PqcryptoProvider(),
  keccak: PqcryptoKeccak(),
  x25519: CryptographyX25519(),
);

/// The same backend with every symmetric primitive taken from PointyCastle.
/// Kept as an alternative (and so the KAT suite exercises both providers).
/// Its ChaCha20-Poly1305 needs 64-bit integers and does not run on
/// JavaScript; its AES-GCM is about ten times slower.
const CryptoBackend pointyCastleCryptoBackend = CryptoBackend(
  symmetric: PointyCastleSymmetricProvider(),
  postQuantum: PqcryptoProvider(),
  keccak: PqcryptoKeccak(),
  x25519: CryptographyX25519(),
);
