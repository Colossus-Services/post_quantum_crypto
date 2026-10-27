import 'dart:io';

import 'package:quantum_crypto/quantum_crypto_io.dart';
import 'package:test/test.dart';

import '../support/test_engine.dart';
import '../unit/key_serialization_test.dart' show fastArgon;

void main() {
  for (final password in [null, 'store password']) {
    group('KeyStore (password: ${password != null})', () {
      late KeyStore store;

      setUp(() {
        store = KeyStore(
          engine,
          InMemoryKeyStorage(),
          password: password,
          parameters: fastArgon,
        );
      });

      test('put, get, list, remove', () async {
        final kp = engine.generateEncryptionKeyPair();
        await store.putPair(kp);
        expect(await store.list(), [kp.keyId]);
        expect(await store.get(kp.keyId), kp.publicKey);
        final priv =
            await store.get(kp.keyId, private: true) as EncryptionPrivateKey;
        expect(priv.keyId, kp.keyId);
        await store.remove(kp.keyId);
        expect(await store.list(), isEmpty);
        expect(await store.get(kp.keyId), isNull);
      });

      test(
        'rotation keeps old data readable and stops new encryption',
        () async {
          final kp = engine.generateEncryptionKeyPair();
          await store.putPair(kp);
          final env = engine.encrypt(
            bytesOf('old'),
            recipients: [kp.publicKey],
          );

          final next = await store.rotateEncryptionKey(kp.keyId);
          expect(next.publicKey.metadata.replaces, kp.keyId);

          final oldPub = await store.get(kp.keyId) as EncryptionPublicKey;
          expect(
            () => engine.encrypt(bytesOf('new'), recipients: [oldPub]),
            throwsA(isA<PolicyViolationException>()),
          );
          final oldPriv =
              await store.get(kp.keyId, private: true) as EncryptionPrivateKey;
          expect(engine.decrypt(env, privateKey: oldPriv), bytesOf('old'));
        },
      );

      test('signing key rotation and revocation', () async {
        final kp = engine.generateSigningKeyPair();
        await store.putPair(kp);
        final next = await store.rotateSigningKey(kp.keyId);
        expect(next.publicKey.metadata.replaces, kp.keyId);
        final oldPriv =
            await store.get(kp.keyId, private: true) as SigningPrivateKey;
        expect(
          () => engine.sign(bytesOf('m'), privateKey: oldPriv),
          throwsA(isA<PolicyViolationException>()),
        );

        await store.revoke(next.keyId, reason: 'compromised');
        final revoked = await store.get(next.keyId) as SigningPublicKey;
        expect(revoked.metadata.isRevoked, isTrue);
        expect(revoked.metadata.revocationReason, 'compromised');
      });

      test('backup and restore', () async {
        final a = engine.generateEncryptionKeyPair();
        final b = engine.generateSigningKeyPair();
        await store.putPair(a);
        await store.putPair(b);
        final backup = await store.backup('backup pw', parameters: fastArgon);

        final restored = KeyStore(engine, InMemoryKeyStorage());
        final ids = await restored.restore(backup, 'backup pw');
        expect(ids.toSet(), {a.keyId, b.keyId});
        expect(await restored.get(b.keyId, private: true), isNotNull);
        await expectLater(
          restored.restore(backup, 'wrong'),
          throwsA(isA<DecryptionFailedException>()),
        );
      });
    });
  }

  test('password-protected store does not hold plaintext seeds', () async {
    final storage = InMemoryKeyStorage();
    final store = KeyStore(
      engine,
      storage,
      password: 'pw',
      parameters: fastArgon,
    );
    final kp = engine.generateEncryptionKeyPair();
    await store.put(kp.privateKey);
    final raw = (await storage.read('${kp.keyId.hex}.key'))!;
    final seed = kp.privateKey.seed;
    final s = String.fromCharCodes(raw);
    expect(s.contains(String.fromCharCodes(seed.sublist(0, 16))), isFalse);
  });

  group('FileKeyStorage', () {
    late Directory dir;

    setUp(() => dir = Directory.systemTemp.createTempSync('qc_keys_'));
    tearDown(() => dir.deleteSync(recursive: true));

    test('persists keys with owner-only permissions', () async {
      final store = KeyStore(engine, FileKeyStorage(dir));
      final kp = engine.generateSigningKeyPair();
      await store.putPair(kp);
      final again = KeyStore(engine, FileKeyStorage(dir));
      expect(await again.get(kp.keyId), kp.publicKey);
      if (!Platform.isWindows) {
        final mode = File(
          '${dir.path}/${kp.keyId.hex}.key',
        ).statSync().modeString();
        expect(mode, 'rw-------');
      }
    });

    test('rejects path-like names', () {
      final s = FileKeyStorage(dir);
      expect(
        () => s.read('../../etc/passwd'),
        throwsA(isA<InvalidInputException>()),
      );
    });
  });
}
