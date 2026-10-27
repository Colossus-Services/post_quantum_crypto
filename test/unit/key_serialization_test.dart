import 'dart:typed_data';

import 'package:post_quantum_crypto/post_quantum_crypto.dart';
import 'package:post_quantum_crypto/src/encoding/der.dart';
import 'package:test/test.dart';

import '../support/test_engine.dart';

/// Small Argon2id parameters so the suite stays fast. They are inside the
/// default [PasswordPolicy] bounds (minimum 8 MiB).
const fastArgon = Argon2idParameters(
  memoryKiB: 8 * 1024,
  iterations: 1,
  parallelism: 1,
);

void main() {
  group('KeyId', () {
    test('is deterministic and algorithm-bound', () {
      final e = deterministicEngine(3);
      final kp = e.generateEncryptionKeyPair();
      final again = engine.importEncryptionPublicKey(kp.publicKey.bytes);
      expect(again.keyId, kp.keyId);
      expect(kp.keyId.bytes, hasLength(32));
      expect(
        kp.keyId.fingerprint,
        matches(RegExp(r'^([0-9a-f]{4}:){7}[0-9a-f]{4}$')),
      );
    });

    test('seed import reproduces the key', () {
      final kp = engine.generateEncryptionKeyPair();
      final again = engine.importEncryptionPrivateKeySeed(kp.privateKey.seed);
      expect(again.keyId, kp.keyId);
      expect(again.publicKey.bytes, kp.publicKey.bytes);
    });
  });

  group('key records', () {
    final metadata = KeyMetadata(
      createdAt: DateTime.utc(2026, 1, 2, 3, 4, 5),
      expiresAt: DateTime.utc(2099),
      usages: const {KeyUsage.encrypt, KeyUsage.decrypt},
      label: 'billing – prod',
    );

    for (final alg in KemAlgorithm.values) {
      test('${alg.standardName} public and private round trip', () {
        final kp = engine.generateEncryptionKeyPair(
          algorithm: alg,
          metadata: metadata,
        );
        final pub = engine.decodeEncryptionPublicKey(
          engine.encodeKey(kp.publicKey),
        );
        expect(pub, kp.publicKey);
        expect(pub.metadata.label, 'billing – prod');
        expect(pub.metadata.expiresAt, DateTime.utc(2099));
        expect(pub.metadata.usages, metadata.usages);

        final priv = engine.decodeEncryptionPrivateKey(
          engine.encodeKey(kp.privateKey),
        );
        expect(priv.keyId, kp.keyId);
        final env = engine.encrypt(bytesOf('x'), recipients: [pub]);
        expect(engine.decrypt(env, privateKey: priv), bytesOf('x'));
      });
    }

    for (final alg in [
      SignatureAlgorithm.mlDsa44,
      SignatureAlgorithm.mlDsa65,
      SignatureAlgorithm.mlDsa87,
    ]) {
      test('${alg.standardName} round trip', () {
        final kp = engine.generateSigningKeyPair(algorithm: alg);
        final priv = engine.decodeSigningPrivateKey(
          engine.encodeKey(kp.privateKey),
        );
        final pub = engine.decodeSigningPublicKey(
          engine.encodeKey(kp.publicKey),
        );
        final sig = engine.sign(bytesOf('m'), privateKey: priv);
        expect(
          engine.verify(bytesOf('m'), signature: sig, publicKey: pub),
          isTrue,
        );
      });
    }

    test('wrong key type is rejected', () {
      final kp = engine.generateEncryptionKeyPair();
      expect(
        () => engine.decodeSigningPublicKey(engine.encodeKey(kp.publicKey)),
        throwsA(isA<InvalidKeyException>()),
      );
    });

    test('private/public mismatch is rejected', () {
      final a = engine.generateEncryptionKeyPair();
      final b = engine.generateEncryptionKeyPair();
      final ra = engine.encodeKey(a.privateKey);
      final rb = engine.encodeKey(b.privateKey);
      // Replace a's seed with b's: header(6)+kind(1)+alg(2)+len(4)+pk+form(1)+len(4).
      final seedOffset = 6 + 1 + 2 + 4 + 1184 + 1 + 4;
      final forged = Uint8List.fromList(ra)
        ..setRange(seedOffset, seedOffset + 64, rb, seedOffset);
      expect(
        () => engine.decodeKey(forged),
        throwsA(isA<InvalidKeyException>()),
      );
    });

    test('truncated and trailing records are malformed', () {
      final r = engine.encodeKey(engine.generateSigningKeyPair().publicKey);
      for (var n = 0; n < r.length; n += 101) {
        expect(
          () => engine.decodeKey(r.sublist(0, n)),
          throwsA(isA<MalformedDataException>()),
        );
      }
      expect(
        () => engine.decodeKey([...r, 1]),
        throwsA(isA<MalformedDataException>()),
      );
    });

    test('invalid ML-KEM public key fails the FIPS 203 modulus check', () {
      final pk = Uint8List.fromList(
        engine.generateEncryptionKeyPair().publicKey.bytes,
      );
      // Set the first 12-bit coefficient to 0xFFF (≥ q = 3329).
      pk[0] = 0xff;
      pk[1] |= 0x0f;
      expect(
        () => engine.importEncryptionPublicKey(pk),
        throwsA(isA<InvalidKeyException>()),
      );
      expect(
        () => engine.importEncryptionPublicKey(pk.sublist(1)),
        throwsA(isA<InvalidKeyException>()),
      );
    });
  });

  group('DER / PEM', () {
    test('ML-KEM SPKI and PKCS#8 (all forms)', () {
      final kp = engine.generateEncryptionKeyPair();
      final spki = engine.exportPublicKeyDer(kp.publicKey);
      expect(spki.sublist(0, 4), [0x30, 0x82, 0x04, 0xb2]);
      expect(engine.importPublicKeyDer(spki), kp.publicKey);
      expect(
        engine.importPublicKeyPem(engine.exportPublicKeyPem(kp.publicKey)),
        kp.publicKey,
      );
      for (final form in PrivateKeyDerForm.values) {
        final der = engine.exportPrivateKeyDer(kp.privateKey, form: form);
        final back = engine.importPrivateKeyDer(der) as EncryptionPrivateKey;
        expect(back.keyId, kp.keyId);
        expect(back.hasSeed, form != PrivateKeyDerForm.expanded);
      }
    });

    test('ML-DSA SPKI and PKCS#8', () {
      final kp = engine.generateSigningKeyPair();
      expect(
        engine.importPublicKeyDer(engine.exportPublicKeyDer(kp.publicKey)),
        kp.publicKey,
      );
      final pem = engine.exportPrivateKeyPem(kp.privateKey);
      expect(pem, startsWith('-----BEGIN PRIVATE KEY-----'));
      final back = engine.importPrivateKeyPem(pem) as SigningPrivateKey;
      expect(back.keyId, kp.keyId);
    });

    test('ML-DSA expanded import needs and checks the public key', () {
      final kp = engine.generateSigningKeyPair();
      final der = engine.exportPrivateKeyDer(
        kp.privateKey,
        form: PrivateKeyDerForm.expanded,
      );
      expect(
        () => engine.importPrivateKeyDer(der),
        throwsA(isA<InvalidKeyException>()),
      );
      final other = engine.generateSigningKeyPair();
      expect(
        () => engine.importSigningPrivateKeyExpanded(
          kp.privateKey.secretKey,
          publicKey: other.publicKey.bytes,
        ),
        throwsA(isA<InvalidKeyException>()),
      );
      final ok = engine.importSigningPrivateKeyExpanded(
        kp.privateKey.secretKey,
        publicKey: kp.publicKey.bytes,
      );
      expect(ok.keyId, kp.keyId);
    });

    for (final alg in SignatureAlgorithm.values) {
      test('${alg.standardName} SPKI and PKCS#8 round trip', () {
        final kp = engine.generateSigningKeyPair(algorithm: alg);
        expect(
          engine.importPublicKeyDer(engine.exportPublicKeyDer(kp.publicKey)),
          kp.publicKey,
        );
        final back =
            engine.importPrivateKeyDer(
                  engine.exportPrivateKeyDer(kp.privateKey),
                )
                as SigningPrivateKey;
        expect(back.keyId, kp.keyId);
        expect(back.publicKey.bytes, kp.publicKey.bytes);
      });
    }

    group('PKCS#8 v2 embedded public key', () {
      // Rebuilds a v1 PKCS#8 as v2 (OneAsymmetricKey, RFC 5958) carrying
      // [publicKey] as the [1] element.
      Uint8List withPublicKey(
        Uint8List v1,
        List<int> publicKey, {
        int version = 1,
      }) {
        final outer = DerReader(v1);
        final seq = DerReader(outer.expect(DerTag.sequence));
        seq.expect(DerTag.integer);
        final algId = seq.expect(DerTag.sequence);
        final privateKey = seq.expect(DerTag.octetString);
        return derSequence([
          derTlv(DerTag.integer, [version]),
          derTlv(DerTag.sequence, algId),
          derTlv(DerTag.octetString, privateKey),
          derTlv(DerTag.contextPrimitive1, [0, ...publicKey]),
        ]);
      }

      test('a matching public key is accepted', () {
        final enc = engine.generateEncryptionKeyPair();
        final encDer = withPublicKey(
          engine.exportPrivateKeyDer(enc.privateKey),
          enc.publicKey.bytes,
        );
        expect(engine.importPrivateKeyDer(encDer).keyId, enc.keyId);

        final sig = engine.generateSigningKeyPair();
        final sigDer = withPublicKey(
          engine.exportPrivateKeyDer(
            sig.privateKey,
            form: PrivateKeyDerForm.expanded,
          ),
          sig.publicKey.bytes,
        );
        expect(engine.importPrivateKeyDer(sigDer).keyId, sig.keyId);
      });

      test('a mismatching public key is rejected', () {
        final enc = engine.generateEncryptionKeyPair();
        final otherEnc = engine.generateEncryptionKeyPair();
        expect(
          () => engine.importPrivateKeyDer(
            withPublicKey(
              engine.exportPrivateKeyDer(enc.privateKey),
              otherEnc.publicKey.bytes,
            ),
          ),
          throwsA(isA<InvalidKeyException>()),
        );

        final sig = engine.generateSigningKeyPair();
        final otherSig = engine.generateSigningKeyPair();
        expect(
          () => engine.importPrivateKeyDer(
            withPublicKey(
              engine.exportPrivateKeyDer(sig.privateKey),
              otherSig.publicKey.bytes,
            ),
          ),
          throwsA(isA<InvalidKeyException>()),
        );
      });

      test('a v1 structure may not carry a public key', () {
        final kp = engine.generateEncryptionKeyPair();
        final v1 = withPublicKey(
          engine.exportPrivateKeyDer(kp.privateKey),
          kp.publicKey.bytes,
          version: 0,
        );
        expect(
          () => engine.importPrivateKeyDer(v1),
          throwsA(isA<MalformedDataException>()),
        );
      });
    });

    test('X-Wing has no DER form', () {
      final kp = engine.generateEncryptionKeyPair(
        algorithm: KemAlgorithm.xWing,
      );
      expect(
        () => engine.exportPublicKeyDer(kp.publicKey),
        throwsA(isA<UnsupportedAlgorithmException>()),
      );
    });

    test('malformed DER is rejected', () {
      final spki = engine.exportPublicKeyDer(
        engine.generateEncryptionKeyPair().publicKey,
      );
      for (final bad in [
        spki.sublist(0, 10),
        [...spki, 0],
        Uint8List.fromList(spki)..[1] = 0x81,
        Uint8List.fromList(spki)..[17] = 0x05,
      ]) {
        expect(
          () => engine.importPublicKeyDer(bad),
          throwsA(isA<PostQuantumCryptoException>()),
        );
      }
    });
  });

  group('password-protected keys (Argon2id + AES-256-GCM)', () {
    test('export, import and change password', () {
      final kp = engine.generateSigningKeyPair(
        metadata: const KeyMetadata(label: 'release signing'),
      );
      final blob = engine.exportPrivateKeyWithPassword(
        kp.privateKey,
        'correct horse',
        parameters: fastArgon,
      );
      expect(String.fromCharCodes(blob), isNot(contains('correct horse')));
      final back =
          engine.importPrivateKeyWithPassword(blob, 'correct horse')
              as SigningPrivateKey;
      expect(back.keyId, kp.keyId);
      expect(back.metadata.label, 'release signing');

      final changed = engine.changeKeyPassword(
        blob,
        oldPassword: 'correct horse',
        newPassword: 'battery staple',
        parameters: fastArgon,
      );
      expect(
        () => engine.importPrivateKeyWithPassword(changed, 'correct horse'),
        throwsA(isA<DecryptionFailedException>()),
      );
      expect(
        engine.importPrivateKeyWithPassword(changed, 'battery staple').keyId,
        kp.keyId,
      );
    });

    test('fresh salt and nonce every time', () {
      final kp = engine.generateEncryptionKeyPair();
      final a = engine.exportPrivateKeyWithPassword(
        kp.privateKey,
        'pw',
        parameters: fastArgon,
      );
      final b = engine.exportPrivateKeyWithPassword(
        kp.privateKey,
        'pw',
        parameters: fastArgon,
      );
      expect(a.sublist(15, 31), isNot(b.sublist(15, 31)));
    });

    test('wrong password and tampering give DecryptionFailed', () {
      final kp = engine.generateEncryptionKeyPair();
      final blob = engine.exportPrivateKeyWithPassword(
        kp.privateKey,
        'pw',
        parameters: fastArgon,
      );
      expect(
        () => engine.importPrivateKeyWithPassword(blob, 'pW'),
        throwsA(isA<DecryptionFailedException>()),
      );
      expect(
        () => engine.importPrivateKeyWithPassword(
          flip(blob, blob.length - 3),
          'pw',
        ),
        throwsA(isA<DecryptionFailedException>()),
      );
      // Salt is authenticated as AAD.
      expect(
        () => engine.importPrivateKeyWithPassword(flip(blob, 20), 'pw'),
        throwsA(isA<DecryptionFailedException>()),
      );
    });

    test('hostile Argon2id parameters are rejected before derivation', () {
      final kp = engine.generateEncryptionKeyPair();
      final blob = engine.exportPrivateKeyWithPassword(
        kp.privateKey,
        'pw',
        parameters: fastArgon,
      );
      // memoryKiB field at offset 7: claim 4 GiB.
      final huge = Uint8List.fromList(blob)
        ..setRange(7, 11, [0xff, 0xff, 0xff, 0xff]);
      final sw = Stopwatch()..start();
      expect(
        () => engine.importPrivateKeyWithPassword(huge, 'pw'),
        throwsA(isA<ResourceLimitExceededException>()),
      );
      expect(sw.elapsedMilliseconds, lessThan(1000));
      expect(
        () => engine.exportPrivateKeyWithPassword(
          kp.privateKey,
          'pw',
          parameters: const Argon2idParameters(
            memoryKiB: 1024,
            iterations: 1,
            parallelism: 1,
          ),
        ),
        throwsA(isA<ResourceLimitExceededException>()),
      );
    });

    test('public keys cannot be password-exported', () {
      expect(
        () => engine.exportPrivateKeyWithPassword(
          engine.generateEncryptionKeyPair().publicKey,
          'pw',
        ),
        throwsA(isA<InvalidInputException>()),
      );
    });
  });

  group('password-based data encryption', () {
    test('round trip with authenticated context', () {
      final blob = engine.encryptWithPassword(
        bytesOf('notes'),
        'pw',
        parameters: fastArgon,
        context: {'app': 'notes'},
      );
      expect(
        engine.decryptWithPassword(
          blob,
          'pw',
          requiredContext: {'app': 'notes'},
        ),
        bytesOf('notes'),
      );
      expect(
        () => engine.decryptWithPassword(
          blob,
          'pw',
          requiredContext: {'app': 'x'},
        ),
        throwsA(isA<ContextMismatchException>()),
      );
      expect(
        () => engine.decryptWithPassword(blob, 'nope'),
        throwsA(isA<DecryptionFailedException>()),
      );
    });

    test('a key export is not accepted as data and vice versa', () {
      final blob = engine.encryptWithPassword(
        bytesOf('x'),
        'pw',
        parameters: fastArgon,
      );
      expect(
        () => engine.importPrivateKeyWithPassword(blob, 'pw'),
        throwsA(isA<UnsupportedFormatException>()),
      );
    });
  });
}
