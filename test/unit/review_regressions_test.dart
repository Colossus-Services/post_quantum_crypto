/// Regression tests for the findings of the PR #1 and PR #3 code reviews.
library;

import 'dart:io';
import 'dart:typed_data';

import 'package:post_quantum_crypto/post_quantum_crypto_io.dart';
import 'package:post_quantum_crypto/src/encoding/der.dart';
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
        throwsA(isA<PostQuantumCryptoException>()),
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

    test('an entry holding another key is rejected', () async {
      final storage = InMemoryKeyStorage();
      final store = KeyStore(engine, storage);
      final a = engine.generateEncryptionKeyPair();
      final b = engine.generateEncryptionKeyPair();
      await store.putPair(a);
      await store.putPair(b);
      // B's files copied over A's.
      for (final ext in ['key', 'pub']) {
        await storage.write(
          '${a.keyId.hex}.$ext',
          (await storage.read('${b.keyId.hex}.$ext'))!,
        );
      }
      for (final private in [false, true]) {
        await expectLater(
          store.get(a.keyId, private: private),
          throwsA(isA<InvalidKeyException>()),
        );
      }
    });

    test('a private record in a public entry is rejected', () async {
      final storage = InMemoryKeyStorage();
      final store = KeyStore(engine, storage);
      final a = engine.generateSigningKeyPair();
      await storage.write('${a.keyId.hex}.pub', engine.encodeKey(a.privateKey));
      await expectLater(
        store.get(a.keyId),
        throwsA(isA<InvalidKeyException>()),
      );
    });

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

    test('a delete issued after a write is not undone by it', () async {
      final s = FileKeyStorage(dir);
      final name = '${'ef' * 32}.pub';
      final writes = [
        for (var i = 0; i < 4; i++) s.write(name, Uint8List.fromList([i])),
      ];
      final deleted = s.delete(name);
      await Future.wait([...writes, deleted]);
      expect(await s.read(name), isNull);
      expect(dir.listSync(), isEmpty);
    });

    test('an invalid name fails the Future, not the call', () async {
      final s = FileKeyStorage(dir);
      final write = s.write('../evil.key', Uint8List(1));
      final delete = s.delete('../evil.key');
      await expectLater(write, throwsA(isA<InvalidInputException>()));
      await expectLater(delete, throwsA(isA<InvalidInputException>()));
    });

    test('stray files are not listed as keys', () async {
      File('${dir.path}/notes.txt').writeAsStringSync('x');
      File('${dir.path}/${'ab' * 32}.key.0011.tmp').writeAsStringSync('x');
      expect(await FileKeyStorage(dir).list(), isEmpty);
    });
  });

  group('strings that would not round-trip are rejected on write', () {
    test('unpaired surrogates in a context', () {
      for (final context in [
        {'\uD800': 'a', '\uDC00': 'b'},
        {'k': 'x\uD800'},
        {'k': '\uDC00x'},
        {'k': 'x\uD800𐀀'},
      ]) {
        expect(
          () => engine.encrypt(
            bytesOf('m'),
            recipients: [kp.publicKey],
            context: context,
          ),
          throwsA(isA<InvalidInputException>()),
        );
      }
    });

    test('an invalid hybrid transcript fails before key establishment', () {
      final responder = engine.generateEncryptionKeyPair(
        algorithm: KemAlgorithm.xWing,
      );
      const bad = HybridTranscript(
        protocol: 'p',
        initiatorId: 'user\uD800',
        responderId: 'server',
      );
      expect(
        () => engine.establishHybridKey(responder.publicKey, transcript: bad),
        throwsA(isA<InvalidInputException>()),
      );
      final ok = engine.establishHybridKey(
        responder.publicKey,
        transcript: const HybridTranscript(
          protocol: 'p',
          initiatorId: 'user',
          responderId: 'server',
        ),
      );
      expect(
        () => engine.acceptHybridKey(
          ok.message,
          privateKey: responder.privateKey,
          transcript: bad,
        ),
        throwsA(isA<InvalidInputException>()),
      );
    });

    test('unpaired surrogates in passwords', () {
      // 'pass\uD800word' and 'pass\uDC00word' must not be the same password.
      expect(
        () => engine.encryptWithPassword(bytesOf('m'), 'pass\uD800word-long'),
        throwsA(isA<InvalidInputException>()),
      );
    });

    test('unpaired surrogates in key labels and manifest paths', () {
      expect(
        () => engine.encodeKey(
          engine
              .generateEncryptionKeyPair(
                metadata: const KeyMetadata(label: 'x\uDC00'),
              )
              .publicKey,
        ),
        throwsA(isA<InvalidInputException>()),
      );
      final signer = engine.generateSigningKeyPair();
      expect(
        () => engine.createSignedManifest([
          engine.manifestEntry('a\uD800b', [1]),
        ], privateKey: signer.privateKey),
        throwsA(isA<InvalidInputException>()),
      );
    });

    test('valid surrogate pairs still round-trip', () {
      const context = {'emoji 😀': 'value 𝄞'};
      final env = engine.encrypt(
        bytesOf('m'),
        recipients: [kp.publicKey],
        context: context,
      );
      expect(
        engine.decrypt(
          env,
          privateKey: kp.privateKey,
          requiredContext: context,
        ),
        bytesOf('m'),
      );
    });

    test('over-long key labels and revocation reasons', () async {
      final long = 'x' * 4097;
      expect(
        () => engine.encodeKey(
          engine
              .generateSigningKeyPair(metadata: KeyMetadata(label: long))
              .publicKey,
        ),
        throwsA(isA<ResourceLimitExceededException>()),
      );
      final ok = engine.generateSigningKeyPair(
        metadata: KeyMetadata(label: 'x' * 4096),
      );
      expect(
        engine.decodeKey(engine.encodeKey(ok.publicKey)).metadata.label,
        hasLength(4096),
      );

      final store = KeyStore(engine, InMemoryKeyStorage());
      await store.putPair(ok);
      await expectLater(
        store.revoke(ok.keyId, reason: long),
        throwsA(isA<ResourceLimitExceededException>()),
      );
      // The failed revoke left the stored key readable.
      expect((await store.get(ok.keyId, private: true))!.keyId, ok.keyId);
    });
  });

  test('an out-of-range metadata date is malformed, not a RangeError', () {
    final created = DateTime.utc(2026, 1, 2, 3, 4, 5, 678);
    final record = engine.encodeKey(
      engine
          .generateEncryptionKeyPair(metadata: KeyMetadata(createdAt: created))
          .publicKey,
    );
    // Locate the big-endian u64 createdAt and replace it with 2^53 - 1,
    // valid as a u64 but beyond DateTime's range.
    final ms = created.millisecondsSinceEpoch;
    final be = [for (var i = 7; i >= 0; i--) (ms >> (8 * i)) & 0xff];
    var at = -1;
    for (var i = 0; i + 8 <= record.length && at < 0; i++) {
      if (List.generate(8, (j) => record[i + j]).join(',') == be.join(',')) {
        at = i;
      }
    }
    expect(at, greaterThan(0));
    final bad = Uint8List.fromList(record)
      ..setRange(at, at + 8, [0x00, 0x1f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff]);
    expect(() => engine.decodeKey(bad), throwsA(isA<MalformedDataException>()));
  });
}
