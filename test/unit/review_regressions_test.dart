/// Regression tests for the findings of the PR #1 code review.
library;

import 'dart:io';
import 'dart:typed_data';

import 'package:quantum_crypto/quantum_crypto_io.dart';
import 'package:quantum_crypto/src/encoding/der.dart';
import 'package:test/test.dart';

import '../support/test_engine.dart';

/// RFC 5958 OneAsymmetricKey tags: `[1] IMPLICIT BIT STRING` publicKey and
/// `[0]` attributes (spelled out so the test does not depend on lib).
const _publicKeyTag = 0x81;
const _attributesTag = 0xa0;

/// A context near the default limits: 64 entries of 64 KiB (~4.2 MB).
Map<String, String> _hugeContext() => {
  for (var i = 0; i < 64; i++)
    'k${i.toString().padLeft(2, '0')}': String.fromCharCodes(
      List.filled(64 * 1024, 0x61 + i % 26),
    ),
};

Stream<List<int>> _pieces(List<int> bytes, int size) async* {
  for (var i = 0; i < bytes.length; i += size) {
    yield bytes.sublist(i, i + size > bytes.length ? bytes.length : i + size);
  }
}

void main() {
  late EncryptionKeyPair kp;
  setUpAll(() => kp = engine.generateEncryptionKeyPair());

  group('stream header limits follow the policy', () {
    late List<int> ct;
    final pt = Uint8List(3000);

    setUpAll(() async {
      // Plus 99 extra recipients (~116 KB), so the header is well past
      // 4 MiB + one 64 KiB read and the old fixed 4 MiB cap always trips.
      final others = [
        for (var i = 0; i < 99; i++)
          engine.generateEncryptionKeyPair().publicKey,
      ];
      ct = await engine
          .encryptStream(
            Stream.value(pt),
            recipients: [kp.publicKey, ...others],
            context: _hugeContext(),
            chunkSize: 1024,
          )
          .expand((c) => c)
          .toList();
      expect(ct.length, greaterThan(4 * 1024 * 1024 + 100 * 1024));
    });

    test('a >4 MiB header the encryptor accepted also decrypts', () async {
      final out = await engine
          .decryptStream(_pieces(ct, 64 * 1024), privateKey: kp.privateKey)
          .expand((c) => c)
          .toList();
      expect(out, pt);
    });

    test(
      'header parsing is not quadratic in the number of input events',
      () async {
        // ~4.3 MB header in 1 KiB events: ~4300 events. Reparsing on every
        // event (the old behaviour) copies and hashes ~9 GB. Parsing with
        // geometric retries touches ~2x the header size.
        final sw = Stopwatch()..start();
        final out = await engine
            .decryptStream(_pieces(ct, 1024), privateKey: kp.privateKey)
            .expand((c) => c)
            .toList();
        expect(out, pt);
        expect(sw.elapsed, lessThan(const Duration(seconds: 10)));
      },
    );

    test('a header beyond the policy cap is rejected', () async {
      final small = engine.withPolicy(
        const SecurityPolicy(
          limits: ResourceLimits(maxContextEntries: 1, maxRecipients: 1),
        ),
      );
      await expectLater(
        small
            .decryptStream(_pieces(ct, 64 * 1024), privateKey: kp.privateKey)
            .drain<void>(),
        throwsA(isA<QuantumCryptoException>()),
      );
    });
  });

  test('signed artifacts with large metadata can be opened', () {
    final signer = engine.generateSigningKeyPair();
    final metadata = {
      for (var i = 0; i < 20; i++)
        'm$i': String.fromCharCodes(List.filled(60000, 0x62)),
    };
    final art = engine.createSignedArtifact(
      bytesOf('content'),
      privateKey: signer.privateKey,
      metadata: metadata,
    );
    expect(art.toBytes().length, greaterThan(1024 * 1024));
    final opened = engine.openSignedArtifact(
      art.toBytes(),
      publicKey: signer.publicKey,
    );
    expect(opened.content, bytesOf('content'));
  });

  group('key store rotation', () {
    test('rotating a retired key yields a usable key', () async {
      final store = KeyStore(engine, InMemoryKeyStorage());
      final a = engine.generateEncryptionKeyPair(
        metadata: const KeyMetadata(
          usages: {KeyUsage.encrypt, KeyUsage.decrypt},
        ),
      );
      await store.putPair(a);
      await store.rotateEncryptionKey(a.keyId);
      // A is now decrypt-only; rotating it again must still produce a key
      // that can be encrypted to.
      final c = await store.rotateEncryptionKey(a.keyId);
      engine.encrypt(bytesOf('m'), recipients: [c.publicKey]);

      final s = engine.generateSigningKeyPair(
        metadata: const KeyMetadata(usages: {KeyUsage.sign, KeyUsage.verify}),
      );
      await store.putPair(s);
      await store.rotateSigningKey(s.keyId);
      final s3 = await store.rotateSigningKey(s.keyId);
      engine.sign(bytesOf('m'), privateKey: s3.privateKey);
    });

    test(
      'revoke and rotate work when only the private half is stored',
      () async {
        final store = KeyStore(engine, InMemoryKeyStorage());
        final a = engine.generateEncryptionKeyPair();
        await store.put(a.privateKey);
        final next = await store.rotateEncryptionKey(a.keyId);
        expect(next.publicKey.metadata.replaces, a.keyId);
        await store.revoke(a.keyId, reason: 'test');
        final priv = await store.get(a.keyId, private: true);
        expect(priv!.metadata.isRevoked, isTrue);
      },
    );

    test('non-key storage entries are ignored by list()', () async {
      final storage = InMemoryKeyStorage();
      await storage.write('not-a-key', Uint8List(1));
      await storage.write('${'zz' * 32}.pub', Uint8List(1));
      expect(await KeyStore(engine, storage).list(), isEmpty);
    });
  });

  group('PKCS#8 strictness', () {
    /// Re-wraps PKCS#8 [der] with [version] and extra trailing [elements].
    Uint8List rewrap(Uint8List der, int version, List<List<int>> elements) {
      final outer = DerReader(der);
      final seq = DerReader(outer.expect(DerTag.sequence));
      seq.expect(DerTag.integer);
      final algId = seq.read();
      final pk = seq.expect(DerTag.octetString);
      return derSequence([
        derTlv(DerTag.integer, [version]),
        derTlv(algId.tag, algId.value),
        derTlv(DerTag.octetString, pk),
        ...elements,
      ]);
    }

    test('trailing garbage is rejected', () {
      final der = engine.exportPrivateKeyDer(kp.privateKey);
      expect(
        () => engine.importPrivateKeyDer(
          rewrap(der, 0, [
            derTlv(DerTag.octetString, [1, 2, 3]),
          ]),
        ),
        throwsA(isA<MalformedDataException>()),
      );
    });

    test('v2 publicKey is checked against the private key', () {
      final der = engine.exportPrivateKeyDer(kp.privateKey);
      final good = rewrap(der, 1, [
        derTlv(_publicKeyTag, [0, ...kp.publicKey.bytes]),
      ]);
      expect(engine.importPrivateKeyDer(good).keyId, kp.keyId);

      final other = engine.generateEncryptionKeyPair();
      final bad = rewrap(der, 1, [
        derTlv(_publicKeyTag, [0, ...other.publicKey.bytes]),
      ]);
      expect(
        () => engine.importPrivateKeyDer(bad),
        throwsA(isA<InvalidKeyException>()),
      );
      // publicKey in a v1 structure is not allowed.
      final v1 = rewrap(der, 0, [
        derTlv(_publicKeyTag, [0, ...kp.publicKey.bytes]),
      ]);
      expect(
        () => engine.importPrivateKeyDer(v1),
        throwsA(isA<MalformedDataException>()),
      );
    });

    test('attributes are allowed; v2 enables expanded-only ML-DSA import', () {
      final s = engine.generateSigningKeyPair();
      final der = engine.exportPrivateKeyDer(
        s.privateKey,
        form: PrivateKeyDerForm.expanded,
      );
      final v2 = rewrap(der, 1, [
        derTlv(_attributesTag, const []),
        derTlv(_publicKeyTag, [0, ...s.publicKey.bytes]),
      ]);
      expect(engine.importPrivateKeyDer(v2).keyId, s.keyId);
    });
  });

  test('public key import validates without encapsulating', () {
    final sw = Stopwatch()..start();
    for (var i = 0; i < 200; i++) {
      engine.importEncryptionPublicKey(kp.publicKey.bytes);
    }
    // Validation is a linear scan; 200 imports should take well under a
    // second even in JIT mode.
    expect(sw.elapsedMilliseconds, lessThan(2000));
  });

  group('FileKeyStorage', () {
    late Directory dir;
    setUp(() => dir = Directory.systemTemp.createTempSync('qc_rev_'));
    tearDown(() => dir.deleteSync(recursive: true));

    test(
      'concurrent writes of one key leave one file and no temporaries',
      () async {
        final s = FileKeyStorage(dir);
        final name = '${'cd' * 32}.key';
        await Future.wait([
          for (var i = 0; i < 8; i++) s.write(name, Uint8List.fromList([i])),
        ]);
        final entries = dir.listSync().map((e) => e.uri.pathSegments.last);
        expect(entries, [name]);
        expect(await s.list(), [name]);
        // Writes through one instance are applied in order.
        expect(await s.read(name), [7]);
        if (!Platform.isWindows) {
          expect(
            File('${dir.path}/$name').statSync().modeString(),
            'rw-------',
          );
        }
      },
    );

    test('stray files are not listed as keys', () async {
      File('${dir.path}/notes.txt').writeAsStringSync('x');
      File('${dir.path}/${'ab' * 32}.key.0011.tmp').writeAsStringSync('x');
      expect(await FileKeyStorage(dir).list(), isEmpty);
    });
  });
}
