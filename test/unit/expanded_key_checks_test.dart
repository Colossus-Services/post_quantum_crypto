/// Consistency checks on imported expanded private keys, one key component
/// at a time, for every parameter set.
///
/// ML-DSA (FIPS 204): sk = rho || K || tr || s1 || s2 || t0; the import
/// recomputes t = A·s1 + s2. SLH-DSA (FIPS 205): sk = SK.seed || SK.prf ||
/// PK.seed || PK.root; the import recomputes PK.root. ML-KEM (FIPS 203): dk
/// = dk_PKE || ek || H(ek) || z; the import checks H(ek) and runs a
/// pairwise-consistency test. Components that the standards leave
/// unconstrained (ML-DSA's K, SLH-DSA's SK.prf, ML-KEM's z) cannot be
/// checked, and these tests pin that down too.
library;

import 'dart:typed_data';

import 'package:post_quantum_crypto/post_quantum_crypto.dart';
import 'package:post_quantum_crypto/src/keys/ml_dsa_expanded.dart';
import 'package:test/test.dart';

import '../support/test_engine.dart';

/// Byte layout of an ML-DSA expanded secret key.
typedef _MlDsaLayout = ({int s1, int s2, int t0, int etaBits});

_MlDsaLayout _layout(SignatureAlgorithm alg) {
  final (k, l, eta) = switch (alg) {
    SignatureAlgorithm.mlDsa44 => (4, 4, 2),
    SignatureAlgorithm.mlDsa65 => (6, 5, 4),
    _ => (8, 7, 2),
  };
  final etaBits = eta == 2 ? 3 : 4;
  final polyBytes = 32 * etaBits;
  const s1 = 128;
  final s2 = s1 + l * polyBytes;
  return (s1: s1, s2: s2, t0: s2 + k * polyBytes, etaBits: etaBits);
}

void main() {
  const mlDsa = [
    SignatureAlgorithm.mlDsa44,
    SignatureAlgorithm.mlDsa65,
    SignatureAlgorithm.mlDsa87,
  ];

  for (final alg in mlDsa) {
    group('${alg.standardName} expanded key', () {
      final kp = deterministicEngine(11).generateSigningKeyPair(algorithm: alg);
      final sk = kp.privateKey.secretKey;
      final layout = _layout(alg);

      /// Imports [mutated] both with the public key and on its own (PKCS#8).
      void expectRejected(Uint8List mutated, String reason) {
        expect(
          () => engine.importSigningPrivateKeyExpanded(
            mutated,
            publicKey: kp.publicKey.bytes,
            algorithm: alg,
          ),
          throwsA(isA<InvalidKeyException>()),
          reason: '$reason (with public key)',
        );
        final der = engine.exportPrivateKeyDer(
          kp.privateKey,
          form: PrivateKeyDerForm.expanded,
        );
        // The expanded key is the last field of the PKCS#8 encoding.
        final patched = Uint8List.fromList(der)
          ..setRange(der.length - mutated.length, der.length, mutated);
        expect(
          () => engine.importPrivateKeyDer(patched),
          throwsA(isA<InvalidKeyException>()),
          reason: '$reason (PKCS#8)',
        );
      }

      Uint8List mutate(void Function(Uint8List) change) =>
          Uint8List.fromList(sk)..apply(change);

      test('the layout matches the key size; the public key is recomputed', () {
        final t0Bytes = (layout.t0 - layout.s2) ~/ (32 * layout.etaBits) * 416;
        expect(layout.t0 + t0Bytes, sk.length);
        expect(mlDsaPublicKeyFromExpanded(alg, sk), kp.publicKey.bytes);
        // The public key is optional on import.
        expect(
          engine.importSigningPrivateKeyExpanded(sk, algorithm: alg).publicKey,
          kp.publicKey,
        );
      });

      test('rho, tr, t0 and in-range s2 changes are detected', () {
        expectRejected(mutate((b) => b[0] ^= 1), 'rho');
        expectRejected(mutate((b) => b[64] ^= 1), 'tr');
        expectRejected(mutate((b) => b[layout.t0] ^= 1), 't0');
        // Another valid s2 coefficient: in range, but t no longer matches.
        expectRejected(mutate((b) => b[layout.s2] ^= 1), 's2 (in range)');
      });

      test('s1 and s2 coefficients out of range are detected', () {
        final mask = (1 << layout.etaBits) - 1; // packed value 2^bits − 1
        for (final start in [layout.s1, layout.s2]) {
          expect(
            () => mlDsaPublicKeyFromExpanded(
              alg,
              mutate((b) => b[start] |= mask),
            ),
            throwsA(
              isA<InvalidKeyException>().having(
                (e) => e.message,
                'message',
                contains('out of range'),
              ),
            ),
          );
        }
      });

      test('the provider leaves the ML-DSA check to the package', () {
        expect(
          () => standardCryptoBackend.postQuantum
              .signature(alg)
              .publicKeyFromSecretKey(sk),
          throwsA(isA<UnsupportedAlgorithmException>()),
        );
      });

      test('K is not constrained by FIPS 204, so it cannot be checked', () {
        final other = mutate((b) => b[32] ^= 1);
        final key = engine.importSigningPrivateKeyExpanded(
          other,
          publicKey: kp.publicKey.bytes,
          algorithm: alg,
        );
        // Still a valid key for the same public key.
        final sig = engine.sign(bytesOf('m'), privateKey: key);
        expect(
          engine.verify(bytesOf('m'), signature: sig, publicKey: kp.publicKey),
          isTrue,
        );
      });
    });
  }

  // The "s" sets work the same way but each check takes 1-2 s; valid keys
  // are covered by the ACVP keyGen vectors, rejection by the slow test below.
  for (final alg in [
    SignatureAlgorithm.slhDsaShake128f,
    SignatureAlgorithm.slhDsaShake192f,
    SignatureAlgorithm.slhDsaShake256f,
  ]) {
    group('${alg.standardName} secret key', () {
      final kp = deterministicEngine(13).generateSigningKeyPair(algorithm: alg);
      final sk = kp.privateKey.secretKey;
      final n = alg.publicKeyLength ~/ 2;

      Uint8List mutate(int index) => Uint8List.fromList(sk)..[index] ^= 1;

      test('key generation uses the package random source', () {
        final again = deterministicEngine(
          13,
        ).generateSigningKeyPair(algorithm: alg);
        expect(again.privateKey.secretKey, sk);
        final other = deterministicEngine(
          14,
        ).generateSigningKeyPair(algorithm: alg);
        expect(other.publicKey, isNot(kp.publicKey));
      });

      test('the unmodified key imports, with or without its public key', () {
        expect(
          engine.importSigningPrivateKeyExpanded(sk, algorithm: alg).publicKey,
          kp.publicKey,
        );
        expect(
          engine
              .importSigningPrivateKeyExpanded(
                sk,
                publicKey: kp.publicKey.bytes,
                algorithm: alg,
              )
              .keyId,
          kp.keyId,
        );
      });

      test('SK.seed, PK.seed and PK.root changes are detected', () {
        final der = engine.exportPrivateKeyDer(kp.privateKey);
        for (final (index, part) in [
          (0, 'SK.seed'),
          (2 * n, 'PK.seed'),
          (3 * n, 'PK.root'),
        ]) {
          final bad = mutate(index);
          expect(
            () => engine.importSigningPrivateKeyExpanded(bad, algorithm: alg),
            throwsA(isA<InvalidKeyException>()),
            reason: part,
          );
          // PKCS#8 (RFC 9909): the raw secret key is the last field.
          final patched = Uint8List.fromList(der)
            ..setRange(der.length - bad.length, der.length, bad);
          expect(
            () => engine.importPrivateKeyDer(patched),
            throwsA(isA<InvalidKeyException>()),
            reason: '$part (PKCS#8)',
          );
        }
      });

      test(
        'SK.prf is not constrained by FIPS 205, so it cannot be checked',
        () {
          // SK.prf only randomizes signing; the key still signs validly.
          final key = engine.importSigningPrivateKeyExpanded(
            mutate(n),
            algorithm: alg,
          );
          expect(key.publicKey, kp.publicKey);
          if (alg == SignatureAlgorithm.slhDsaShake128f) {
            final sig = engine.sign(bytesOf('m'), privateKey: key);
            expect(
              engine.verify(
                bytesOf('m'),
                signature: sig,
                publicKey: kp.publicKey,
              ),
              isTrue,
            );
          }
        },
      );

      test('loading a key record can skip the check', () {
        // A record with a corrupted SK.seed: the stored public key still
        // matches the PK.seed || PK.root the secret key embeds.
        final record = engine.encodeKey(kp.privateKey);
        final at = _indexOf(record, sk);
        final bad = Uint8List.fromList(record)..[at] ^= 1;
        expect(
          () => engine.decodeKey(bad),
          throwsA(isA<InvalidKeyException>()),
        );
        final key = engine.decodeSigningPrivateKey(bad, verifySlhDsaKey: false);
        expect(key.publicKey, kp.publicKey);
        // An unchecked inconsistent key loads, but its signatures fail.
        if (alg == SignatureAlgorithm.slhDsaShake128f) {
          final sig = engine.sign(bytesOf('m'), privateKey: key);
          expect(
            engine.verify(
              bytesOf('m'),
              signature: sig,
              publicKey: kp.publicKey,
            ),
            isFalse,
          );
        }
        // The stored public key is compared either way.
        // The public key field precedes the secret key in the record.
        final otherPk = Uint8List.fromList(record)
          ..[_indexOf(record, kp.publicKey.bytes)] ^= 1;
        expect(
          () => engine.decodeKey(otherPk, verifySlhDsaKey: false),
          throwsA(isA<InvalidKeyException>()),
        );
      });
    });
  }

  group('provider key generation', () {
    final pq = standardCryptoBackend.postQuantum;

    test('ML-DSA generate is seeded key generation', () {
      final p = pq.signature(SignatureAlgorithm.mlDsa44);
      final randomness = Uint8List(p.keyGenerationRandomnessLength)..[0] = 1;
      expect(
        p.generate(randomness).publicKey,
        p.generateFromSeed(randomness).publicKey,
      );
    });

    test('SLH-DSA has no seed form and checks its randomness length', () {
      final p = pq.signature(SignatureAlgorithm.slhDsaShake128f);
      expect(p.seedLength, isNull);
      expect(
        () => p.generateFromSeed(Uint8List(48)),
        throwsA(isA<UnsupportedAlgorithmException>()),
      );
      expect(
        () => p.generate(Uint8List(p.keyGenerationRandomnessLength - 1)),
        throwsA(isA<InvalidInputException>()),
      );
    });
  });

  test('password imports and the key store pass the option through', () async {
    const alg = SignatureAlgorithm.slhDsaShake128f;
    final kp = engine.generateSigningKeyPair(algorithm: alg);
    final protected = engine.exportPrivateKeyWithPassword(
      kp.privateKey,
      'pw',
      parameters: fastArgon,
    );
    for (final verify in [true, false]) {
      expect(
        engine
            .importPrivateKeyWithPassword(
              protected,
              'pw',
              verifySlhDsaKey: verify,
            )
            .keyId,
        kp.keyId,
      );
    }
    final store = KeyStore(
      engine,
      InMemoryKeyStorage(),
      password: 'pw',
      parameters: fastArgon,
    );
    await store.putPair(kp);
    final key = await store.get(
      kp.keyId,
      private: true,
      verifySlhDsaKey: false,
    );
    expect(key!.keyId, kp.keyId);
  });

  test('SLH-DSA-SHAKE-128s: a PK.root change is detected', () {
    const alg = SignatureAlgorithm.slhDsaShake128s;
    final kp = deterministicEngine(13).generateSigningKeyPair(algorithm: alg);
    final rootAt = 3 * (alg.publicKeyLength ~/ 2);
    final bad = Uint8List.fromList(kp.privateKey.secretKey)..[rootAt] ^= 1;
    expect(
      () => engine.importSigningPrivateKeyExpanded(bad, algorithm: alg),
      throwsA(isA<InvalidKeyException>()),
    );
  }, tags: ['slow']);

  for (final alg in [
    KemAlgorithm.mlKem512,
    KemAlgorithm.mlKem768,
    KemAlgorithm.mlKem1024,
  ]) {
    group('${alg.standardName} expanded key', () {
      final kp = deterministicEngine(
        12,
      ).generateEncryptionKeyPair(algorithm: alg);
      final dk = kp.privateKey.secret.part(0);
      final k = (alg.publicKeyLength - 32) ~/ 384;
      final ekAt = 384 * k;
      final hashAt = ekAt + alg.publicKeyLength;
      final zAt = hashAt + 32;

      Uint8List mutate(int index) => Uint8List.fromList(dk)..[index] ^= 1;

      EncryptionPrivateKey import(Uint8List bytes) =>
          engine.importEncryptionPrivateKeyExpanded(bytes, algorithm: alg);

      test('the unmodified key imports', () {
        expect(import(dk).publicKey, kp.publicKey);
      });

      test('s (pairwise consistency), ek and H(ek) changes are detected', () {
        for (final (index, part) in [
          (0, 's'),
          (ekAt, 'ek'),
          (hashAt, 'H(ek)'),
        ]) {
          expect(
            () => import(mutate(index)),
            throwsA(isA<InvalidKeyException>()),
            reason: part,
          );
        }
      });

      test('z is not constrained by FIPS 203, so it cannot be checked', () {
        // z only feeds implicit rejection; honest ciphertexts still decrypt.
        final key = import(mutate(zAt));
        final env = engine.encrypt(bytesOf('m'), recipients: [kp.publicKey]);
        expect(engine.decrypt(env, privateKey: key), bytesOf('m'));
      });
    });
  }
}

extension on Uint8List {
  void apply(void Function(Uint8List) change) => change(this);
}

/// Index of the first occurrence of [part] in [data].
int _indexOf(Uint8List data, List<int> part) {
  outer:
  for (var i = 0; i + part.length <= data.length; i++) {
    for (var j = 0; j < part.length; j++) {
      if (data[i + j] != part[j]) continue outer;
    }
    return i;
  }
  throw StateError('not found');
}
