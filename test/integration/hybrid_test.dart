import 'package:post_quantum_crypto/post_quantum_crypto.dart';
import 'package:test/test.dart';

import '../support/test_engine.dart';

void main() {
  late EncryptionKeyPair server;
  const t = HybridTranscript(
    protocol: 'example/sync/v1',
    initiatorId: 'client-7',
    responderId: 'server-1',
    extra: {'session': 'abc'},
  );

  setUpAll(() {
    server = engine.generateEncryptionKeyPair(algorithm: KemAlgorithm.xWing);
  });

  test('both sides derive the same key', () {
    final init = engine.establishHybridKey(server.publicKey, transcript: t);
    expect(init.sessionKey, hasLength(32));
    final k = engine.acceptHybridKey(
      init.message,
      privateKey: server.privateKey,
      transcript: t,
    );
    expect(k, init.sessionKey);
  });

  test('custom key length', () {
    final init = engine.establishHybridKey(
      server.publicKey,
      transcript: t,
      length: 64,
    );
    expect(
      engine.acceptHybridKey(
        init.message,
        privateKey: server.privateKey,
        transcript: t,
        length: 64,
      ),
      init.sessionKey,
    );
  });

  test('transcript mismatch yields a different key', () {
    final init = engine.establishHybridKey(server.publicKey, transcript: t);
    for (final other in [
      const HybridTranscript(
        protocol: 'example/sync/v2',
        initiatorId: 'client-7',
        responderId: 'server-1',
        extra: {'session': 'abc'},
      ),
      const HybridTranscript(
        protocol: 'example/sync/v1',
        initiatorId: 'client-8',
        responderId: 'server-1',
        extra: {'session': 'abc'},
      ),
      const HybridTranscript(
        protocol: 'example/sync/v1',
        initiatorId: 'client-7',
        responderId: 'server-1',
      ),
    ]) {
      expect(
        engine.acceptHybridKey(
          init.message,
          privateKey: server.privateKey,
          transcript: other,
        ),
        isNot(init.sessionKey),
      );
    }
  });

  test('tampered encapsulation yields a different key', () {
    final init = engine.establishHybridKey(server.publicKey, transcript: t);
    for (final i in [100, init.message.length - 1]) {
      expect(
        engine.acceptHybridKey(
          flip(init.message, i),
          privateKey: server.privateKey,
          transcript: t,
        ),
        isNot(init.sessionKey),
      );
    }
  });

  test('downgrade to a non-hybrid KEM is rejected', () {
    final plain = engine.generateEncryptionKeyPair();
    expect(
      () => engine.establishHybridKey(plain.publicKey, transcript: t),
      throwsA(isA<PolicyViolationException>()),
    );
    final init = engine.establishHybridKey(server.publicKey, transcript: t);
    // Rewrite the KEM id to ML-KEM-768 (0x0041).
    final m = init.message.toList()
      ..[6] = 0x00
      ..[7] = 0x41;
    expect(
      () => engine.acceptHybridKey(
        m,
        privateKey: server.privateKey,
        transcript: t,
      ),
      throwsA(isA<PolicyViolationException>()),
    );
  });

  test('message for another key is rejected', () {
    final other = engine.generateEncryptionKeyPair(
      algorithm: KemAlgorithm.xWing,
    );
    final init = engine.establishHybridKey(server.publicKey, transcript: t);
    expect(
      () => engine.acceptHybridKey(
        init.message,
        privateKey: other.privateKey,
        transcript: t,
      ),
      throwsA(isA<KeyNotFoundException>()),
    );
  });

  test('truncated message is malformed', () {
    final init = engine.establishHybridKey(server.publicKey, transcript: t);
    expect(
      () => engine.acceptHybridKey(
        init.message.sublist(0, 500),
        privateKey: server.privateKey,
        transcript: t,
      ),
      throwsA(isA<MalformedDataException>()),
    );
  });
}
