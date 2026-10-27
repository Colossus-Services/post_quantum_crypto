import 'dart:io';
import 'dart:typed_data';

import 'package:post_quantum_crypto/post_quantum_crypto_io.dart';
import 'package:post_quantum_crypto/src/encoding/bytes.dart';
import 'package:post_quantum_crypto/src/encoding/canonical.dart';
import 'package:test/test.dart';

import '../support/test_engine.dart';
import 'key_serialization_test.dart' show fastArgon;

void main() {
  group('raw key import', () {
    test(
      'ML-KEM expanded decapsulation key: import, use, record round trip',
      () {
        final kp = engine.generateEncryptionKeyPair();
        final dk = engine.exportPrivateKeyDer(
          kp.privateKey,
          form: PrivateKeyDerForm.expanded,
        );
        final expanded =
            (engine.importPrivateKeyDer(dk) as EncryptionPrivateKey);
        expect(expanded.hasSeed, isFalse);
        expect(expanded.keyId, kp.keyId);
        expect(
          () => engine.exportPrivateKeyDer(expanded),
          throwsA(isA<InvalidKeyException>()),
        );

        final env = engine.encrypt(bytesOf('m'), recipients: [kp.publicKey]);
        final viaRecord = engine.decodeEncryptionPrivateKey(
          engine.encodeKey(expanded),
        );
        expect(viaRecord.hasSeed, isFalse);
        expect(engine.decrypt(env, privateKey: viaRecord), bytesOf('m'));
      },
    );

    test('wrong lengths are rejected with InvalidKeyException', () {
      expect(
        () => engine.importEncryptionPrivateKeySeed(Uint8List(32)),
        throwsA(isA<InvalidKeyException>()),
      );
      expect(
        () => engine.importEncryptionPrivateKeyExpanded(Uint8List(100)),
        throwsA(isA<InvalidKeyException>()),
      );
      expect(
        () => engine.importSigningPublicKey(Uint8List(100)),
        throwsA(isA<InvalidKeyException>()),
      );
      expect(
        () => engine.importSigningPrivateKeySeed(Uint8List(31)),
        throwsA(isA<InvalidKeyException>()),
      );
      expect(
        () => engine.importEncryptionPrivateKeyExpanded(
          Uint8List(32),
          algorithm: KemAlgorithm.xWing,
        ),
        throwsA(isA<InvalidKeyException>()),
      );
    });

    test('tampered ML-KEM expanded key fails the FIPS 203 hash check', () {
      final kp = engine.generateEncryptionKeyPair();
      // Expanded-only, so the FIPS 203 H(ek) check (not the seed comparison)
      // is what must catch it.
      final der = engine.exportPrivateKeyDer(
        kp.privateKey,
        form: PrivateKeyDerForm.expanded,
      );
      // dk = dk_PKE || ek || H(ek) || z: flip a byte inside ek.
      final bad = flip(der, der.length - 200);
      expect(
        () => engine.importPrivateKeyDer(bad),
        throwsA(isA<InvalidKeyException>()),
      );
    });

    test('ML-DSA seed/expanded mismatch in PKCS#8 "both" is rejected', () {
      final a = engine.generateSigningKeyPair();
      final b = engine.generateSigningKeyPair();
      final da = engine.exportPrivateKeyDer(
        a.privateKey,
        form: PrivateKeyDerForm.both,
      );
      final db = engine.exportPrivateKeyDer(
        b.privateKey,
        form: PrivateKeyDerForm.both,
      );
      // Same layout: splice b's expanded key after a's seed.
      final splitAt = da.length - SignatureAlgorithm.mlDsa65.publicKeyLength;
      final mixed = Uint8List.fromList([
        ...da.sublist(0, splitAt),
        ...db.sublist(splitAt),
      ]);
      expect(
        () => engine.importPrivateKeyDer(mixed),
        throwsA(isA<InvalidKeyException>()),
      );
    });

    test('key equality and hash codes', () {
      final kp = engine.generateSigningKeyPair();
      final again = engine.importSigningPublicKey(kp.publicKey.bytes);
      expect(again, kp.publicKey);
      expect(again.hashCode, kp.publicKey.hashCode);
      expect({kp.publicKey, again}, hasLength(1));
      expect(kp.publicKey.bytes, isA<Uint8List>());
      expect(() => kp.publicKey.bytes[0] = 1, throwsUnsupportedError);
      expect(kp.privateKey.toString(), contains('<redacted>'));
      expect(kp.keyId.toString(), startsWith('KeyId('));
    });

    test('destroyed signing key cannot sign', () {
      final kp = engine.generateSigningKeyPair();
      kp.privateKey.destroy();
      expect(kp.privateKey.isDestroyed, isTrue);
      expect(
        () => engine.sign(bytesOf('m'), privateKey: kp.privateKey),
        throwsA(isA<InvalidKeyException>()),
      );
    });
  });

  group('signature policy', () {
    test('prohibited and below-category algorithms', () {
      final kp44 = engine.generateSigningKeyPair(
        algorithm: SignatureAlgorithm.mlDsa44,
      );
      final strict = engine.withPolicy(SecurityPolicy.strict);
      expect(
        () => strict.sign(bytesOf('m'), privateKey: kp44.privateKey),
        throwsA(isA<PolicyViolationException>()),
      );
      final noSlh = engine.withPolicy(
        const SecurityPolicy(allowedSignatures: {SignatureAlgorithm.mlDsa65}),
      );
      expect(
        () => noSlh.generateSigningKeyPair(
          algorithm: SignatureAlgorithm.slhDsaShake128f,
        ),
        throwsA(isA<PolicyViolationException>()),
      );
      final sig = engine.sign(bytesOf('m'), privateKey: kp44.privateKey);
      expect(
        () => strict.verify(
          bytesOf('m'),
          signature: sig,
          publicKey: kp44.publicKey,
        ),
        throwsA(isA<PolicyViolationException>()),
      );
    });

    test('prohibited KEM', () {
      final only768 = engine.withPolicy(
        const SecurityPolicy(allowedKems: {KemAlgorithm.mlKem768}),
      );
      expect(
        () => only768.generateEncryptionKeyPair(
          algorithm: KemAlgorithm.mlKem1024,
        ),
        throwsA(isA<PolicyViolationException>()),
      );
    });

    test('injected clock decides expiry; copyWith keeps other fields', () {
      final kp = engine.generateEncryptionKeyPair();
      final key = kp.publicKey.withMetadata(
        KeyMetadata(expiresAt: DateTime.utc(2030)),
      );
      final in2029 = engine.withPolicy(
        SecurityPolicy(clock: () => DateTime.utc(2029)),
      );
      in2029.encrypt(bytesOf('m'), recipients: [key]);
      final in2031 = engine.withPolicy(
        in2029.policy.copyWith(clock: () => DateTime.utc(2031)),
      );
      expect(
        () => in2031.encrypt(bytesOf('m'), recipients: [key]),
        throwsA(isA<PolicyViolationException>()),
      );
      final lenient = engine.withPolicy(
        in2031.policy.copyWith(rejectExpiredKeys: false),
      );
      lenient.encrypt(bytesOf('m'), recipients: [key]);
      expect(lenient.policy.minimumSecurityCategory, 1);
    });
  });

  group('canonical map limits', () {
    const limits = (maxEntries: 2, maxKeyBytes: 4, maxValueBytes: 8);

    test('encoder enforces limits and rejects empty keys', () {
      expect(
        () => CanonicalMap.encode({'a': '', 'b': '', 'c': ''}, limits),
        throwsA(isA<ResourceLimitExceededException>()),
      );
      expect(
        () => CanonicalMap.encode({'': 'x'}, limits),
        throwsA(isA<InvalidInputException>()),
      );
      expect(
        () => CanonicalMap.encode({'abcde': 'x'}, limits),
        throwsA(isA<ResourceLimitExceededException>()),
      );
      expect(
        () => CanonicalMap.encode({'a': '123456789'}, limits),
        throwsA(isA<ResourceLimitExceededException>()),
      );
    });

    test('decoder enforces limits, order and UTF-8', () {
      Map<String, String> decode(List<int> b) => parseStrict(
        () => CanonicalMap.read(ByteReader(Uint8List.fromList(b)), limits),
      );
      expect(decode(CanonicalMap.encode({'b': '2', 'a': '1'}, limits)), {
        'a': '1',
        'b': '2',
      });
      // Three entries declared.
      expect(
        () => decode([0, 3]),
        throwsA(isA<ResourceLimitExceededException>()),
      );
      // Empty key.
      expect(
        () => decode([0, 1, 0, 0, 0, 0, 0]),
        throwsA(isA<MalformedDataException>()),
      );
      // Out of order: "b" then "a".
      expect(
        () => decode([0, 2, 1, 0x62, 0, 0, 0, 0, 1, 0x61, 0, 0, 0, 0]),
        throwsA(isA<MalformedDataException>()),
      );
      // Duplicate key.
      expect(
        () => decode([0, 2, 1, 0x61, 0, 0, 0, 0, 1, 0x61, 0, 0, 0, 0]),
        throwsA(isA<MalformedDataException>()),
      );
      // Invalid UTF-8 value.
      expect(
        () => decode([0, 1, 1, 0x61, 0, 0, 0, 1, 0xff]),
        throwsA(isA<MalformedDataException>()),
      );
      // Value longer than allowed.
      expect(
        () => decode([0, 1, 1, 0x61, 0, 0, 0, 9, ...List.filled(9, 0x30)]),
        throwsA(isA<ResourceLimitExceededException>()),
      );
    });

    test('envelope context respects the policy limits', () {
      final kp = engine.generateEncryptionKeyPair();
      final small = engine.withPolicy(
        const SecurityPolicy(limits: ResourceLimits(maxContextEntries: 1)),
      );
      expect(
        () => small.encrypt(
          bytesOf('m'),
          recipients: [kp.publicKey],
          context: {'a': '1', 'b': '2'},
        ),
        throwsA(isA<ResourceLimitExceededException>()),
      );
      final env = engine.encrypt(
        bytesOf('m'),
        recipients: [kp.publicKey],
        context: {'a': '1', 'b': '2'},
      );
      expect(
        () => small.parseEnvelope(env.toBytes()),
        throwsA(isA<ResourceLimitExceededException>()),
      );
    });
  });

  group('password parameters', () {
    test('defaults come from the policy', () {
      expect(engine.defaultArgon2idParameters.memoryKiB, 64 * 1024);
      expect(engine.defaultArgon2idParameters.iterations, 3);
      expect(engine.defaultArgon2idParameters.toString(), contains('m='));
    });

    test('every bound is enforced', () {
      final kp = engine.generateEncryptionKeyPair();
      for (final p in [
        const Argon2idParameters(
          memoryKiB: 8192,
          iterations: 0,
          parallelism: 1,
        ),
        const Argon2idParameters(
          memoryKiB: 8192,
          iterations: 99,
          parallelism: 1,
        ),
        const Argon2idParameters(
          memoryKiB: 8192,
          iterations: 1,
          parallelism: 0,
        ),
        const Argon2idParameters(
          memoryKiB: 8192,
          iterations: 1,
          parallelism: 99,
        ),
        const Argon2idParameters(
          memoryKiB: 2 * 1024 * 1024,
          iterations: 1,
          parallelism: 1,
        ),
      ]) {
        expect(
          () => engine.exportPrivateKeyWithPassword(
            kp.privateKey,
            'pw',
            parameters: p,
          ),
          throwsA(isA<ResourceLimitExceededException>()),
          reason: '$p',
        );
      }
    });

    test('minimum password length', () {
      final strict = engine.withPolicy(
        const SecurityPolicy(password: PasswordPolicy(minPasswordBytes: 12)),
      );
      expect(
        () => strict.encryptWithPassword(
          bytesOf('x'),
          'short',
          parameters: fastArgon,
        ),
        throwsA(isA<InvalidInputException>()),
      );
      expect(
        () =>
            engine.encryptWithPassword(bytesOf('x'), '', parameters: fastArgon),
        throwsA(isA<InvalidInputException>()),
      );
    });

    test('changeKeyPassword works for encryption keys too', () {
      final kp = engine.generateEncryptionKeyPair();
      final blob = engine.exportPrivateKeyWithPassword(
        kp.privateKey,
        'a',
        parameters: fastArgon,
      );
      final changed = engine.changeKeyPassword(
        blob,
        oldPassword: 'a',
        newPassword: 'b',
        parameters: fastArgon,
      );
      expect(engine.importPrivateKeyWithPassword(changed, 'b').keyId, kp.keyId);
    });
  });

  group('encodings', () {
    test('ByteWriter rejects out-of-range integers', () {
      final w = ByteWriter();
      expect(() => w.u8(256), throwsA(isA<InvalidInputException>()));
      expect(() => w.u16(-1), throwsA(isA<InvalidInputException>()));
      expect(
        () => w.u64(9007199254740992),
        throwsA(isA<InvalidInputException>()),
      );
      expect(() => w.fixed([1, 2], 3), throwsA(isA<InvalidInputException>()));
    });

    test('u64 round trip near the 2^53 bound', () {
      const v = 9007199254740991;
      final w = ByteWriter()..u64(v);
      expect(ByteReader(w.toBytes()).u64(), v);
      expect(
        () => ByteReader(Uint8List.fromList(List.filled(8, 0xff))).u64(),
        throwsA(isA<MalformedDataException>()),
      );
    });

    test('PEM label must match', () {
      final pem = engine.exportPublicKeyPem(
        engine.generateSigningKeyPair().publicKey,
      );
      expect(
        () => engine.importPrivateKeyPem(pem),
        throwsA(isA<MalformedDataException>()),
      );
    });

    test('negative random length is rejected', () {
      expect(
        () => SystemSecureRandom.instance.nextBytes(-1),
        throwsA(isA<InvalidInputException>()),
      );
    });

    test('SHA3-256 incremental sink equals one-shot', () {
      final h = engine.ctx.hash(HashAlgorithm.sha3_256);
      final sink = h.start()
        ..add([1, 2, 3])
        ..add([4]);
      expect(sink.close(), h.hash([1, 2, 3, 4]));
    });
  });

  group('FileKeyStorage', () {
    late Directory dir;

    setUp(() => dir = Directory.systemTemp.createTempSync('qc_fks_'));
    tearDown(() {
      if (dir.existsSync()) dir.deleteSync(recursive: true);
    });

    test('list on a missing directory, delete', () async {
      final missing = FileKeyStorage(Directory('${dir.path}/nope'));
      expect(await missing.list(), isEmpty);
      final s = FileKeyStorage(dir);
      final name = '${'ab' * 32}.pub';
      await s.write(name, Uint8List.fromList([1, 2, 3]));
      expect(await s.list(), [name]);
      expect(await s.read(name), [1, 2, 3]);
      await s.delete(name);
      await s.delete(name); // idempotent
      expect(await s.read(name), isNull);
    });
  });
}
