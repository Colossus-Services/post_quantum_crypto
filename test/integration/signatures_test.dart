import 'dart:typed_data';

import 'package:quantum_crypto/quantum_crypto.dart';
import 'package:test/test.dart';

import '../support/test_engine.dart';

void main() {
  late SigningKeyPair signer;
  late SigningKeyPair other;

  setUpAll(() {
    signer = engine.generateSigningKeyPair();
    other = engine.generateSigningKeyPair();
  });

  group('raw FIPS 204 signatures', () {
    test('sign and verify with context', () {
      final msg = bytesOf('release 1.0.0');
      final sig = engine.sign(
        msg,
        privateKey: signer.privateKey,
        context: bytesOf('app/release'),
      );
      expect(sig, hasLength(SignatureAlgorithm.mlDsa65.signatureLength));
      expect(
        engine.verify(
          msg,
          signature: sig,
          publicKey: signer.publicKey,
          context: bytesOf('app/release'),
        ),
        isTrue,
      );
    });

    test('rejects modified message, signature, context and key', () {
      final msg = bytesOf('m');
      final sig = engine.sign(msg, privateKey: signer.privateKey);
      final pk = signer.publicKey;
      expect(
        engine.verify(bytesOf('n'), signature: sig, publicKey: pk),
        isFalse,
      );
      expect(
        engine.verify(msg, signature: flip(sig, 10), publicKey: pk),
        isFalse,
      );
      expect(
        engine.verify(msg, signature: sig.sublist(1), publicKey: pk),
        isFalse,
      );
      expect(
        engine.verify(msg, signature: sig, publicKey: pk, context: [1]),
        isFalse,
      );
      expect(
        engine.verify(msg, signature: sig, publicKey: other.publicKey),
        isFalse,
      );
    });

    test('hedged: two signatures of the same message differ', () {
      final a = engine.sign(bytesOf('m'), privateKey: signer.privateKey);
      final b = engine.sign(bytesOf('m'), privateKey: signer.privateKey);
      expect(a, isNot(b));
    });

    test('context over 255 bytes is rejected', () {
      expect(
        () => engine.sign(
          bytesOf('m'),
          privateKey: signer.privateKey,
          context: Uint8List(256),
        ),
        throwsA(isA<InvalidInputException>()),
      );
    });

    for (final alg in [
      SignatureAlgorithm.mlDsa44,
      SignatureAlgorithm.mlDsa87,
    ]) {
      test(alg.standardName, () {
        final kp = engine.generateSigningKeyPair(algorithm: alg);
        final sig = engine.sign(bytesOf('m'), privateKey: kp.privateKey);
        expect(sig, hasLength(alg.signatureLength));
        expect(
          engine.verify(bytesOf('m'), signature: sig, publicKey: kp.publicKey),
          isTrue,
        );
      });
    }

    test('SLH-DSA-SHAKE-128f', () {
      final kp = engine.generateSigningKeyPair(
        algorithm: SignatureAlgorithm.slhDsaShake128f,
      );
      expect(kp.publicKey.bytes, hasLength(32));
      final sig = engine.sign(bytesOf('m'), privateKey: kp.privateKey);
      expect(sig, hasLength(17088));
      expect(
        engine.verify(bytesOf('m'), signature: sig, publicKey: kp.publicKey),
        isTrue,
      );
      expect(
        engine.verify(bytesOf('x'), signature: sig, publicKey: kp.publicKey),
        isFalse,
      );
      final back = engine.decodeSigningPrivateKey(
        engine.encodeKey(kp.privateKey),
      );
      expect(back.keyId, kp.keyId);
    }, tags: ['slow']);
  });

  group('detached signatures', () {
    test('sign, serialize, parse, verify', () {
      final content = Uint8List.fromList(List.generate(5000, (i) => i));
      final sig = engine.signDetached(
        content,
        privateKey: signer.privateKey,
        context: bytesOf('docs'),
        metadata: {'content-type': 'text/plain', 'name': 'a.txt'},
      );
      final parsed = engine.parseDetachedSignature(sig.toBytes());
      expect(parsed.signerKeyId, signer.keyId);
      expect(parsed.contentLength, 5000);
      final v = engine.verifyDetached(
        content,
        signature: parsed,
        publicKey: signer.publicKey,
      );
      expect(v.metadata['name'], 'a.txt');
      expect(v.context, bytesOf('docs'));
    });

    test('modified content, metadata or signer is rejected', () {
      final content = bytesOf('contract v1');
      final sig = engine.signDetached(
        content,
        privateKey: signer.privateKey,
        metadata: {'version': '1'},
      );
      expect(
        () => engine.verifyDetached(
          bytesOf('contract v2'),
          signature: sig,
          publicKey: signer.publicKey,
        ),
        throwsA(isA<SignatureVerificationException>()),
      );
      expect(
        () => engine.verifyDetached(
          content,
          signature: sig,
          publicKey: other.publicKey,
        ),
        throwsA(isA<SignatureVerificationException>()),
      );
      final bytes = sig.toBytes();
      final i = String.fromCharCodes(bytes).indexOf('version') + 11;
      final tampered = Uint8List.fromList(bytes)..[i] = '2'.codeUnitAt(0);
      expect(
        () => engine.verifyDetached(
          content,
          signature: engine.parseDetachedSignature(tampered),
          publicKey: signer.publicKey,
        ),
        throwsA(isA<SignatureVerificationException>()),
      );
    });

    test('every bit flip in the serialization is rejected', () {
      final content = bytesOf('x');
      final bytes = engine
          .signDetached(content, privateKey: signer.privateKey)
          .toBytes();
      for (var i = 0; i < bytes.length; i += 13) {
        expect(
          () {
            final s = engine.parseDetachedSignature(flip(bytes, i, i % 8));
            engine.verifyDetached(
              content,
              signature: s,
              publicKey: signer.publicKey,
            );
          },
          throwsA(isA<QuantumCryptoException>()),
          reason: 'byte $i',
        );
      }
    });

    test('stream signing equals one-shot digest binding', () async {
      final chunks = [
        for (var i = 0; i < 50; i++) Uint8List.fromList(List.filled(1000, i)),
      ];
      final all = Uint8List.fromList(chunks.expand((c) => c).toList());
      final sig = await engine.signStream(
        Stream.fromIterable(chunks),
        privateKey: signer.privateKey,
      );
      expect(sig.contentLength, all.length);
      engine.verifyDetached(all, signature: sig, publicKey: signer.publicKey);
      await engine.verifyStream(
        Stream.fromIterable(chunks),
        signature: sig,
        publicKey: signer.publicKey,
      );
      await expectLater(
        engine.verifyStream(
          Stream.fromIterable(chunks.take(49)),
          signature: sig,
          publicKey: signer.publicKey,
        ),
        throwsA(isA<SignatureVerificationException>()),
      );
    });
  });

  group('signed artifacts', () {
    test('open returns verified content', () {
      final art = engine.createSignedArtifact(
        bytesOf('payload'),
        privateKey: signer.privateKey,
        metadata: {'type': 'config'},
      );
      final opened = engine.openSignedArtifact(
        art.toBytes(),
        publicKey: signer.publicKey,
      );
      expect(opened.content, bytesOf('payload'));
      expect(opened.verified.metadata['type'], 'config');
    });

    test('tampered content is rejected', () {
      final bytes = engine
          .createSignedArtifact(
            bytesOf('payload'),
            privateKey: signer.privateKey,
          )
          .toBytes();
      expect(
        () => engine.openSignedArtifact(
          flip(bytes, bytes.length - 1),
          publicKey: signer.publicKey,
        ),
        throwsA(isA<SignatureVerificationException>()),
      );
    });
  });

  group('signed manifests', () {
    List<ManifestEntry> entries() => [
      engine.manifestEntry('bin/app', bytesOf('binary')),
      engine.manifestEntry('README.md', bytesOf('# readme')),
      engine.manifestEntry('lib/a.dart', bytesOf('void main() {}')),
    ];

    test('sign, parse, verify; entries are canonical', () {
      final m = engine.createSignedManifest(
        entries(),
        privateKey: signer.privateKey,
        metadata: {'release': '1.0.0'},
      );
      final parsed = engine.parseSignedManifest(m.toBytes());
      expect(parsed.entries.map((e) => e.path), [
        'README.md',
        'bin/app',
        'lib/a.dart',
      ]);
      engine.verifyManifest(parsed, publicKey: signer.publicKey);
      expect(parsed['bin/app']!.size, 6);
      // Entry order does not change the encoding.
      final m2 = engine.createSignedManifest(
        entries().reversed.toList(),
        privateKey: signer.privateKey,
        metadata: {'release': '1.0.0'},
      );
      expect(
        m2.toBytes().sublist(0, m2.toBytes().length - 3309),
        m.toBytes().sublist(0, m.toBytes().length - 3309),
      );
    });

    test('duplicate and unsafe paths are rejected', () {
      expect(
        () => engine.createSignedManifest([
          engine.manifestEntry('a', bytesOf('1')),
          engine.manifestEntry('a', bytesOf('2')),
        ], privateKey: signer.privateKey),
        throwsA(isA<InvalidInputException>()),
      );
      for (final p in [
        '/etc/passwd',
        '../x',
        'a/../b',
        'a\\b',
        'C:x',
        'a//b',
        '',
      ]) {
        expect(
          () => engine.manifestEntry(p, bytesOf('1')),
          throwsA(isA<InvalidInputException>()),
          reason: p,
        );
      }
    });

    test('tampered manifest is rejected', () {
      final bytes = engine
          .createSignedManifest(entries(), privateKey: signer.privateKey)
          .toBytes();
      // Flip a digest byte of the first entry.
      final i = String.fromCharCodes(bytes).indexOf('README.md') + 9 + 8 + 3;
      expect(
        () => engine.verifyManifest(
          engine.parseSignedManifest(flip(bytes, i)),
          publicKey: signer.publicKey,
        ),
        throwsA(isA<SignatureVerificationException>()),
      );
    });
  });

  group('trust evaluation is separate from verification', () {
    test('decisions', () {
      final sig = engine.signDetached(
        bytesOf('m'),
        privateKey: signer.privateKey,
      );
      final v = engine.verifyDetached(
        bytesOf('m'),
        signature: sig,
        publicKey: signer.publicKey,
      );
      expect(TrustStore().evaluate(v), TrustDecision.unknownSigner);
      final store = TrustStore([signer.publicKey]);
      expect(store.lookup(sig.signerKeyId), signer.publicKey);
      expect(store.evaluate(v), TrustDecision.trusted);
      store.trust(
        signer.publicKey.withMetadata(
          KeyMetadata(revokedAt: DateTime.utc(2025)),
        ),
      );
      expect(store.evaluate(v), TrustDecision.revoked);
      store.trust(
        signer.publicKey.withMetadata(
          KeyMetadata(expiresAt: DateTime.utc(2025)),
        ),
      );
      expect(store.evaluate(v), TrustDecision.expired);
      store.distrust(signer.keyId);
      expect(store.evaluate(v), TrustDecision.unknownSigner);
    });

    test('policy rejects verification with a revoked key', () {
      final sig = engine.sign(bytesOf('m'), privateKey: signer.privateKey);
      expect(
        () => engine.verify(
          bytesOf('m'),
          signature: sig,
          publicKey: signer.publicKey.withMetadata(
            KeyMetadata(revokedAt: DateTime.utc(2025)),
          ),
        ),
        throwsA(isA<PolicyViolationException>()),
      );
    });
  });
}
