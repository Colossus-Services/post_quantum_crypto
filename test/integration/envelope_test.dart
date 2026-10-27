import 'dart:typed_data';

import 'package:post_quantum_crypto/post_quantum_crypto.dart';
import 'package:test/test.dart';

import '../support/test_engine.dart';

void main() {
  late EncryptionKeyPair alice;
  late EncryptionKeyPair bob;
  late EncryptionKeyPair carol;
  late EncryptionKeyPair hybrid;

  setUpAll(() {
    alice = engine.generateEncryptionKeyPair();
    bob = engine.generateEncryptionKeyPair();
    carol = engine.generateEncryptionKeyPair(algorithm: KemAlgorithm.mlKem1024);
    hybrid = engine.generateEncryptionKeyPair(algorithm: KemAlgorithm.xWing);
  });

  group('single recipient', () {
    test('round trip with independently generated keys', () {
      final pt = bytesOf('attack at dawn');
      final env = engine.encrypt(pt, recipients: [alice.publicKey]);
      expect(env.recipients.single.keyId, alice.keyId);
      expect(env.payloadLength, pt.length);
      expect(engine.decrypt(env, privateKey: alice.privateKey), pt);
    });

    test('serialized envelope decrypts after a separate parse', () {
      final pt = Uint8List.fromList(List.generate(10000, (i) => i * 7));
      final bytes = engine.encrypt(pt, recipients: [alice.publicKey]).toBytes();
      expect(engine.decryptBytes(bytes, privateKey: alice.privateKey), pt);
    });

    test('empty plaintext', () {
      final env = engine.encrypt(const [], recipients: [alice.publicKey]);
      expect(engine.decrypt(env, privateKey: alice.privateKey), isEmpty);
    });

    test('ChaCha20-Poly1305 suite', () {
      final env = engine.encrypt(
        bytesOf('x'),
        recipients: [alice.publicKey],
        aead: AeadAlgorithm.chacha20Poly1305,
      );
      expect(env.aead, AeadAlgorithm.chacha20Poly1305);
      expect(engine.decrypt(env, privateKey: alice.privateKey), bytesOf('x'));
    });

    test('X-Wing hybrid recipient', () {
      final env = engine.encrypt(bytesOf('h'), recipients: [hybrid.publicKey]);
      expect(env.recipients.single.algorithm, KemAlgorithm.xWing);
      expect(engine.decrypt(env, privateKey: hybrid.privateKey), bytesOf('h'));
    });

    test('two encryptions of the same plaintext differ', () {
      final a = engine.encrypt(bytesOf('m'), recipients: [alice.publicKey]);
      final b = engine.encrypt(bytesOf('m'), recipients: [alice.publicKey]);
      expect(a.toBytes(), isNot(b.toBytes()));
    });

    test('wrong key is reported as not-a-recipient', () {
      final env = engine.encrypt(bytesOf('m'), recipients: [alice.publicKey]);
      expect(
        () => engine.decrypt(env, privateKey: bob.privateKey),
        throwsA(isA<KeyNotFoundException>()),
      );
    });
  });

  group('multiple recipients', () {
    test('each recipient decrypts with its own key', () {
      final pt = bytesOf('shared secret document');
      final env = engine.encrypt(
        pt,
        recipients: [
          alice.publicKey,
          bob.publicKey,
          carol.publicKey,
          hybrid.publicKey,
        ],
      );
      expect(env.recipients, hasLength(4));
      for (final k in [alice, bob, carol, hybrid]) {
        expect(engine.decrypt(env, privateKey: k.privateKey), pt);
      }
    });

    test('duplicate recipients are rejected', () {
      expect(
        () => engine.encrypt(
          bytesOf('m'),
          recipients: [alice.publicKey, alice.publicKey],
        ),
        throwsA(isA<InvalidInputException>()),
      );
    });

    test('no recipients is rejected', () {
      expect(
        () => engine.encrypt(bytesOf('m'), recipients: const []),
        throwsA(isA<InvalidInputException>()),
      );
    });

    test('add and remove recipients with a fresh data key', () {
      final pt = bytesOf('rotating access');
      final env = engine.encrypt(pt, recipients: [alice.publicKey]);
      final added = engine.addRecipients(
        env,
        privateKey: alice.privateKey,
        currentRecipients: [alice.publicKey],
        newRecipients: [bob.publicKey],
      );
      expect(engine.decrypt(added, privateKey: bob.privateKey), pt);
      expect(engine.decrypt(added, privateKey: alice.privateKey), pt);

      final removed = engine.removeRecipients(
        added,
        privateKey: bob.privateKey,
        currentRecipients: [alice.publicKey, bob.publicKey],
        remove: {alice.keyId},
      );
      expect(removed.recipients.single.keyId, bob.keyId);
      expect(
        () => engine.decrypt(removed, privateKey: alice.privateKey),
        throwsA(isA<KeyNotFoundException>()),
      );
      expect(engine.decrypt(removed, privateKey: bob.privateKey), pt);
    });

    test('recipient-entry substitution breaks authentication', () {
      // Build two envelopes for {alice, bob} and splice alice's entry from
      // one into the other: the wrap authenticates (same header) but the
      // payload AAD covers the full recipient list, so decryption fails.
      final pt = bytesOf('m');
      final e1 = engine.encrypt(
        pt,
        recipients: [alice.publicKey, bob.publicKey],
      );
      final e2 = engine.encrypt(
        pt,
        recipients: [alice.publicKey, bob.publicKey],
      );
      final b1 = e1.toBytes();
      final b2 = e2.toBytes();
      // Header: 6 + 2 + 2 + 2 (empty context) = 12; count u16 = 2 bytes.
      const recordStart = 14;
      final recordLen =
          2 + 32 + KemAlgorithm.mlKem768.ciphertextLength + 32 + 16;
      final spliced = Uint8List.fromList(b2)
        ..setRange(recordStart, recordStart + recordLen, b1, recordStart);
      expect(
        () => engine.decryptBytes(spliced, privateKey: alice.privateKey),
        throwsA(isA<DecryptionFailedException>()),
      );
      // Bob's own entry is intact but the payload AAD changed too.
      expect(
        () => engine.decryptBytes(spliced, privateKey: bob.privateKey),
        throwsA(isA<DecryptionFailedException>()),
      );
    });
  });

  group('authenticated context', () {
    final ctx = {'tenant': 'acme', 'record': '42', 'purpose': 'invoice'};

    test('is authenticated and returned', () {
      final env = engine.encrypt(
        bytesOf('m'),
        recipients: [alice.publicKey],
        context: ctx,
      );
      expect(env.context, ctx);
      expect(
        engine.decrypt(
          env,
          privateKey: alice.privateKey,
          requiredContext: {'tenant': 'acme'},
        ),
        bytesOf('m'),
      );
    });

    test('required context mismatch is rejected', () {
      final env = engine.encrypt(
        bytesOf('m'),
        recipients: [alice.publicKey],
        context: ctx,
      );
      expect(
        () => engine.decrypt(
          env,
          privateKey: alice.privateKey,
          requiredContext: {'tenant': 'other'},
        ),
        throwsA(isA<ContextMismatchException>()),
      );
      expect(
        () => engine.decrypt(
          env,
          privateKey: alice.privateKey,
          requiredContext: {'missing': 'x'},
        ),
        throwsA(isA<ContextMismatchException>()),
      );
    });

    test('modified context fails authentication', () {
      final env = engine.encrypt(
        bytesOf('m'),
        recipients: [alice.publicKey],
        context: {'tenant': 'acme'},
      );
      final bytes = env.toBytes();
      final i = String.fromCharCodes(bytes).indexOf('acme');
      final tampered = Uint8List.fromList(bytes)..[i] = 'b'.codeUnitAt(0);
      expect(
        () => engine.decryptBytes(tampered, privateKey: alice.privateKey),
        throwsA(isA<DecryptionFailedException>()),
      );
    });

    test('context encoding is canonical regardless of insertion order', () {
      final e = deterministicEngine(7);
      final f = deterministicEngine(7);
      final kp = e.generateEncryptionKeyPair();
      f.generateEncryptionKeyPair();
      final a = e.encrypt(
        bytesOf('m'),
        recipients: [kp.publicKey],
        context: {'a': '1', 'b': '2'},
      );
      final b = f.encrypt(
        bytesOf('m'),
        recipients: [kp.publicKey],
        context: {'b': '2', 'a': '1'},
      );
      expect(a.toBytes(), b.toBytes());
    });
  });

  group('tampering', () {
    late Uint8List bytes;

    setUpAll(() {
      bytes = engine
          .encrypt(bytesOf('sensitive payload'), recipients: [alice.publicKey])
          .toBytes();
    });

    test('every single-bit flip is rejected', () {
      // Flip one bit in every byte position (covers header, KEM ciphertext,
      // wrapped key, nonce, ciphertext and tag).
      for (var i = 0; i < bytes.length; i += 1) {
        final t = flip(bytes, i, i % 8);
        expect(
          () => engine.decryptBytes(t, privateKey: alice.privateKey),
          throwsA(isA<PostQuantumCryptoException>()),
          reason: 'byte $i',
        );
      }
    });

    test('ciphertext and tag modifications give DecryptionFailed', () {
      for (final i in [
        bytes.length - 1,
        bytes.length - 17,
        bytes.length - 20,
      ]) {
        expect(
          () =>
              engine.decryptBytes(flip(bytes, i), privateKey: alice.privateKey),
          throwsA(isA<DecryptionFailedException>()),
        );
      }
    });

    test('KEM ciphertext modification gives DecryptionFailed '
        '(implicit rejection)', () {
      expect(
        () =>
            engine.decryptBytes(flip(bytes, 100), privateKey: alice.privateKey),
        throwsA(isA<DecryptionFailedException>()),
      );
    });

    test('truncation at every length is rejected as malformed', () {
      for (var n = 0; n < bytes.length; n += 37) {
        expect(
          () => engine.decryptBytes(
            bytes.sublist(0, n),
            privateKey: alice.privateKey,
          ),
          throwsA(isA<MalformedDataException>()),
          reason: 'length $n',
        );
      }
    });

    test('trailing bytes are rejected', () {
      expect(
        () => engine.parseEnvelope([...bytes, 0]),
        throwsA(isA<MalformedDataException>()),
      );
    });

    test('unknown version and type are rejected', () {
      // Version 1 (package 1.x) is not read either, with or without
      // acceptLegacyFormats.
      final legacy = engine.withPolicy(
        SecurityPolicy.standard.copyWith(acceptLegacyFormats: true),
      );
      for (final version in [0, 1, 3, 0xff]) {
        final other = Uint8List.fromList(bytes)..[4] = version;
        for (final e in [engine, legacy]) {
          expect(
            () => e.parseEnvelope(other),
            throwsA(isA<UnsupportedFormatException>()),
          );
        }
      }
      expect(
        () => engine.parseEnvelope(Uint8List.fromList(bytes)..[5] = 9),
        throwsA(isA<UnsupportedFormatException>()),
      );
    });

    test('unknown AEAD and KEM identifiers are rejected', () {
      expect(
        () => engine.parseEnvelope(Uint8List.fromList(bytes)..[9] = 0x77),
        throwsA(isA<UnsupportedAlgorithmException>()),
      );
      expect(
        () => engine.parseEnvelope(Uint8List.fromList(bytes)..[15] = 0x77),
        throwsA(isA<UnsupportedAlgorithmException>()),
      );
    });

    test('oversized length fields are rejected before allocation', () {
      final small = engine.withPolicy(
        const SecurityPolicy(
          limits: ResourceLimits(maxEnvelopePayloadBytes: 4),
        ),
      );
      expect(
        () => small.parseEnvelope(bytes),
        throwsA(isA<ResourceLimitExceededException>()),
      );
      expect(
        () => small.encrypt(bytesOf('12345'), recipients: [alice.publicKey]),
        throwsA(isA<ResourceLimitExceededException>()),
      );
    });
  });

  group('policy', () {
    test('prohibited AEAD is rejected before decapsulation', () {
      final env = engine.encrypt(
        bytesOf('m'),
        recipients: [alice.publicKey],
        aead: AeadAlgorithm.chacha20Poly1305,
      );
      final strict = engine.withPolicy(
        const SecurityPolicy(allowedAeads: {AeadAlgorithm.aes256Gcm}),
      );
      expect(
        () => strict.decrypt(env, privateKey: alice.privateKey),
        throwsA(isA<PolicyViolationException>()),
      );
    });

    test('minimum security category', () {
      final small = engine.generateEncryptionKeyPair(
        algorithm: KemAlgorithm.mlKem512,
      );
      final strict = engine.withPolicy(SecurityPolicy.strict);
      expect(
        () => strict.encrypt(bytesOf('m'), recipients: [small.publicKey]),
        throwsA(isA<PolicyViolationException>()),
      );
      expect(
        () =>
            strict.generateEncryptionKeyPair(algorithm: KemAlgorithm.mlKem512),
        throwsA(isA<PolicyViolationException>()),
      );
    });

    test('hybrid-only policy rejects pure ML-KEM recipients', () {
      final hybridOnly = engine.withPolicy(
        const SecurityPolicy(requireHybridKem: true),
      );
      expect(
        () => hybridOnly.encrypt(bytesOf('m'), recipients: [alice.publicKey]),
        throwsA(isA<PolicyViolationException>()),
      );
      hybridOnly.encrypt(bytesOf('m'), recipients: [hybrid.publicKey]);
    });

    test('expired and revoked keys are rejected', () {
      final expired = alice.publicKey.withMetadata(
        KeyMetadata(expiresAt: DateTime.utc(2000)),
      );
      expect(
        () => engine.encrypt(bytesOf('m'), recipients: [expired]),
        throwsA(isA<PolicyViolationException>()),
      );
      final revoked = alice.publicKey.withMetadata(
        KeyMetadata(revokedAt: DateTime.utc(2020), revocationReason: 'lost'),
      );
      expect(
        () => engine.encrypt(bytesOf('m'), recipients: [revoked]),
        throwsA(isA<PolicyViolationException>()),
      );
      final env = engine.encrypt(bytesOf('m'), recipients: [alice.publicKey]);
      expect(
        () => engine.decrypt(
          env,
          privateKey: alice.privateKey.withMetadata(
            KeyMetadata(expiresAt: DateTime.utc(2000)),
          ),
        ),
        throwsA(isA<PolicyViolationException>()),
      );
    });

    test('key usage restrictions', () {
      final decryptOnly = alice.publicKey.withMetadata(
        const KeyMetadata(usages: {KeyUsage.decrypt}),
      );
      expect(
        () => engine.encrypt(bytesOf('m'), recipients: [decryptOnly]),
        throwsA(isA<PolicyViolationException>()),
      );
    });
  });

  test('private keys never print key material', () {
    final s = alice.privateKey.toString();
    expect(s, contains('<redacted>'));
    expect(s, isNot(contains(TextEncoding.toHex(alice.privateKey.seed))));
  });

  test('destroyed keys cannot be used', () {
    final kp = engine.generateEncryptionKeyPair();
    final env = engine.encrypt(bytesOf('m'), recipients: [kp.publicKey]);
    kp.privateKey.destroy();
    expect(
      () => engine.decrypt(env, privateKey: kp.privateKey),
      throwsA(isA<InvalidKeyException>()),
    );
  });
}
