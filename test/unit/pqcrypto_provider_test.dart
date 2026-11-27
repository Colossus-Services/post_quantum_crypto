/// Error translation at the `package:pqcrypto` boundary.
///
/// The public API validates keys before they reach the provider, so these
/// paths are only reachable by calling the provider directly. They pin that
/// pqcrypto's own key rejections (ArgumentError) surface as this package's
/// [InvalidKeyException], whatever pqcrypto version is resolved.
library;

import 'dart:typed_data';

import 'package:post_quantum_crypto/post_quantum_crypto.dart';
import 'package:post_quantum_crypto/src/providers/pqcrypto_provider.dart';
import 'package:test/test.dart';

void main() {
  const provider = PqcryptoProvider();

  group('ML-KEM', () {
    final kem = provider.mlKem(KemAlgorithm.mlKem768);
    final seed = Uint8List.fromList(List.generate(64, (i) => i));
    final pair = kem.generateFromSeed(seed);
    final m = Uint8List(32);

    test('X-Wing is not a provider KEM', () {
      expect(
        () => provider.mlKem(KemAlgorithm.xWing),
        throwsA(isA<UnsupportedAlgorithmException>()),
      );
    });

    test('encapsulate rejects a key failing the modulus check', () {
      // 0xFF 0xFF encodes a first coefficient of 4095 >= q (3329).
      final badPublicKey = Uint8List.fromList(pair.publicKey)
        ..[0] = 0xFF
        ..[1] = 0xFF;
      expect(
        () => kem.encapsulate(badPublicKey, m),
        throwsA(isA<InvalidKeyException>()),
      );
    });

    test('encapsulate rejects a key of the wrong length', () {
      expect(
        () => kem.encapsulate(Uint8List(10), m),
        throwsA(isA<InvalidKeyException>()),
      );
    });

    test('decapsulate rejects a secret key with a wrong public-key hash', () {
      final encapsulation = kem.encapsulate(pair.publicKey, m);
      // The hash H(ek) occupies the 32 bytes before the final 32-byte z.
      final badSecretKey = Uint8List.fromList(pair.secretKey);
      badSecretKey[badSecretKey.length - 64] ^= 0x01;
      expect(
        () => kem.decapsulate(badSecretKey, encapsulation.ciphertext),
        throwsA(isA<InvalidKeyException>()),
      );
    });

    test('a valid pair still round-trips', () {
      final encapsulation = kem.encapsulate(pair.publicKey, m);
      expect(
        kem.decapsulate(pair.secretKey, encapsulation.ciphertext),
        encapsulation.sharedSecret,
      );
    });
  });
}
