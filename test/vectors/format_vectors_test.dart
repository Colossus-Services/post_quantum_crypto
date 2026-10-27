/// Published format vectors: `post_quantum_crypto_v2.json` (current format,
/// reproduced byte for byte) and `post_quantum_crypto_v1.json` (frozen 1.x
/// output, read as legacy input).
@Tags(['vectors'])
library;

import 'dart:convert';

import 'package:post_quantum_crypto/post_quantum_crypto.dart';
import 'package:test/test.dart';

import '../support/test_engine.dart';
import '../support/vectors.dart';
import 'format_vectors.dart';

/// Engine that reads legacy (format 1) objects.
final legacyEngine = engine.withPolicy(
  SecurityPolicy.standard.copyWith(acceptLegacyFormats: true),
);

void main() {
  group('v2 (current)', () {
    final v =
        loadVectors('post_quantum_crypto_v2.json') as Map<String, dynamic>;
    _checkVectors(v, engine);

    test('the generator reproduces the published file byte for byte', () async {
      final rebuilt = jsonDecode(jsonEncode(await buildFormatVectors()));
      expect(rebuilt, v);
    });

    test('objects carry format version 2', () {
      final envelope = engine.parseEnvelope(hex(v['envelope']));
      expect(envelope.formatVersion, 2);
    });
  });

  group('v1 (legacy, frozen 1.x output)', () {
    final v =
        loadVectors('post_quantum_crypto_v1.json') as Map<String, dynamic>;
    _checkVectors(v, legacyEngine);

    test('envelopes, streams and password objects need the legacy policy', () {
      final keys = v['keys'] as Map<String, dynamic>;
      final mlkem = engine.importEncryptionPrivateKeySeed(
        hex((keys['mlKem768'] as Map)['seed']),
      );
      expect(
        () => engine.decryptBytes(hex(v['envelope']), privateKey: mlkem),
        throwsA(isA<UnsupportedFormatException>()),
      );
      expect(
        engine.decryptStream(Stream.value(hex(v['stream'])), privateKey: mlkem),
        emitsError(isA<UnsupportedFormatException>()),
      );
      final p = v['passwordProtectedKey'] as Map<String, dynamic>;
      expect(
        () => engine.importPrivateKeyWithPassword(
          hex(p['blob']),
          p['password'] as String,
        ),
        throwsA(isA<UnsupportedFormatException>()),
      );
      expect(legacyEngine.parseEnvelope(hex(v['envelope'])).formatVersion, 1);
    });

    test('unchanged object types are still format 1 and need no opt-in', () {
      // Signatures, manifests, hybrid messages and key records did not
      // change, so the current engine reads 1.x output as is.
      _checkSignaturesAndKeys(v, engine);
    });
  });
}

void _checkVectors(Map<String, dynamic> v, PostQuantumCryptoEngine e) {
  final keys = v['keys'] as Map<String, dynamic>;
  Map<String, dynamic> k(String name) => keys[name] as Map<String, dynamic>;

  // Keys are rebuilt from their seeds only; nothing else is trusted.
  final mlkem = e.importEncryptionPrivateKeySeed(hex(k('mlKem768')['seed']));
  final xwing = e.importEncryptionPrivateKeySeed(
    hex(k('xWing')['seed']),
    algorithm: KemAlgorithm.xWing,
  );
  final plaintext = hex(v['plaintext']);
  final context = (v['context'] as Map).cast<String, String>();

  test('keys match published public keys and ids', () {
    expect(mlkem.publicKey.bytes, hex(k('mlKem768')['publicKey']));
    expect(mlkem.keyId.hex, k('mlKem768')['keyId']);
    expect(xwing.publicKey.bytes, hex(k('xWing')['publicKey']));
    expect(xwing.keyId.hex, k('xWing')['keyId']);
  });

  test('envelope decrypts for both recipients', () {
    for (final key in [mlkem, xwing]) {
      expect(
        e.decryptBytes(
          hex(v['envelope']),
          privateKey: key,
          requiredContext: context,
        ),
        plaintext,
      );
    }
    expect(
      e.decryptBytes(hex(v['envelopeChaCha20Poly1305']), privateKey: mlkem),
      plaintext,
    );
  });

  test('stream decrypts', () async {
    final out = await e
        .decryptStream(Stream.value(hex(v['stream'])), privateKey: mlkem)
        .expand((c) => c)
        .toList();
    expect(out, hex(v['streamPlaintext']));
  });

  test('password-protected key', () {
    final p = v['passwordProtectedKey'] as Map<String, dynamic>;
    final restored = e.importPrivateKeyWithPassword(
      hex(p['blob']),
      p['password'] as String,
    );
    expect(restored.keyId.hex, k('mlDsa65')['keyId']);
  });

  test('signatures, hybrid message and key record', () {
    _checkSignaturesAndKeys(v, e);
  });
}

void _checkSignaturesAndKeys(
  Map<String, dynamic> v,
  PostQuantumCryptoEngine e,
) {
  final keys = v['keys'] as Map<String, dynamic>;
  Map<String, dynamic> k(String name) => keys[name] as Map<String, dynamic>;
  final mlkem = e.importEncryptionPrivateKeySeed(hex(k('mlKem768')['seed']));
  final xwing = e.importEncryptionPrivateKeySeed(
    hex(k('xWing')['seed']),
    algorithm: KemAlgorithm.xWing,
  );
  final mldsa = e.importSigningPrivateKeySeed(hex(k('mlDsa65')['seed']));
  final plaintext = hex(v['plaintext']);

  expect(mldsa.publicKey.bytes, hex(k('mlDsa65')['publicKey']));
  expect(mldsa.keyId.hex, k('mlDsa65')['keyId']);
  expect(
    e.verify(
      plaintext,
      signature: hex(v['rawSignature']),
      publicKey: mldsa.publicKey,
      context: hex(v['signatureContext']),
    ),
    isTrue,
  );
  final d = e.parseDetachedSignature(hex(v['detachedSignature']));
  expect(
    e
        .verifyDetached(plaintext, signature: d, publicKey: mldsa.publicKey)
        .metadata,
    {'name': 'message.txt'},
  );
  e.verifyManifest(
    e.parseSignedManifest(hex(v['manifest'])),
    publicKey: mldsa.publicKey,
  );
  final h = v['hybrid'] as Map<String, dynamic>;
  expect(
    e.acceptHybridKey(
      hex(h['message']),
      privateKey: xwing,
      transcript: formatTranscript,
    ),
    hex(h['sessionKey']),
  );
  expect(e.decodeKey(hex(v['keyRecordPublic'])), mlkem.publicKey);
}
