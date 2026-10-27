/// Published post_quantum_crypto format v2 vectors
/// (`test/vectors/post_quantum_crypto_v2.json`).
@Tags(['vectors'])
library;

import 'dart:convert';
import 'dart:typed_data';

import 'package:post_quantum_crypto/post_quantum_crypto.dart';
import 'package:test/test.dart';

import '../support/test_engine.dart';
import '../support/vectors.dart';
import 'format_vectors.dart';

void main() {
  final v = loadVectors('post_quantum_crypto_v2.json') as Map<String, dynamic>;
  final keys = v['keys'] as Map<String, dynamic>;
  Map<String, dynamic> k(String name) => keys[name] as Map<String, dynamic>;

  // Keys are rebuilt from their seeds only; nothing else is trusted.
  final mlkem = engine.importEncryptionPrivateKeySeed(
    hex(k('mlKem768')['seed']),
  );
  final xwing = engine.importEncryptionPrivateKeySeed(
    hex(k('xWing')['seed']),
    algorithm: KemAlgorithm.xWing,
  );
  final mldsa = engine.importSigningPrivateKeySeed(hex(k('mlDsa65')['seed']));
  final plaintext = hex(v['plaintext']);
  final context = (v['context'] as Map).cast<String, String>();

  test('keys match published public keys and ids', () {
    expect(mlkem.publicKey.bytes, hex(k('mlKem768')['publicKey']));
    expect(mlkem.keyId.hex, k('mlKem768')['keyId']);
    expect(xwing.publicKey.bytes, hex(k('xWing')['publicKey']));
    expect(xwing.keyId.hex, k('xWing')['keyId']);
    expect(mldsa.publicKey.bytes, hex(k('mlDsa65')['publicKey']));
    expect(mldsa.keyId.hex, k('mlDsa65')['keyId']);
  });

  test('every object carries format version 2', () {
    for (final name in [
      'envelope',
      'envelopeChaCha20Poly1305',
      'stream',
      'detachedSignature',
      'manifest',
      'keyRecordPublic',
    ]) {
      expect(hex(v[name])[4], 2, reason: name);
    }
    expect(engine.parseEnvelope(hex(v['envelope'])).formatVersion, 2);
  });

  test('another format version is rejected', () {
    for (final version in [1, 3]) {
      expect(
        () => engine.parseEnvelope(
          Uint8List.fromList(hex(v['envelope']))..[4] = version,
        ),
        throwsA(isA<UnsupportedFormatException>()),
      );
    }
  });

  test('envelope decrypts for both recipients', () {
    for (final key in [mlkem, xwing]) {
      expect(
        engine.decryptBytes(
          hex(v['envelope']),
          privateKey: key,
          requiredContext: context,
        ),
        plaintext,
      );
    }
    expect(
      engine.decryptBytes(
        hex(v['envelopeChaCha20Poly1305']),
        privateKey: mlkem,
      ),
      plaintext,
    );
  });

  test('stream decrypts', () async {
    final out = await engine
        .decryptStream(Stream.value(hex(v['stream'])), privateKey: mlkem)
        .expand((c) => c)
        .toList();
    expect(out, hex(v['streamPlaintext']));
  });

  test('signatures verify', () {
    expect(
      engine.verify(
        plaintext,
        signature: hex(v['rawSignature']),
        publicKey: mldsa.publicKey,
        context: hex(v['signatureContext']),
      ),
      isTrue,
    );
    final d = engine.parseDetachedSignature(hex(v['detachedSignature']));
    expect(
      engine
          .verifyDetached(plaintext, signature: d, publicKey: mldsa.publicKey)
          .metadata,
      {'name': 'message.txt'},
    );
    engine.verifyManifest(
      engine.parseSignedManifest(hex(v['manifest'])),
      publicKey: mldsa.publicKey,
    );
  });

  test('hybrid session key', () {
    final h = v['hybrid'] as Map<String, dynamic>;
    expect(
      engine.acceptHybridKey(
        hex(h['message']),
        privateKey: xwing,
        transcript: formatTranscript,
      ),
      hex(h['sessionKey']),
    );
  });

  test('key record and password-protected key', () {
    expect(engine.decodeKey(hex(v['keyRecordPublic'])), mlkem.publicKey);
    final p = v['passwordProtectedKey'] as Map<String, dynamic>;
    final restored = engine.importPrivateKeyWithPassword(
      hex(p['blob']),
      p['password'] as String,
    );
    expect(restored.keyId, mldsa.keyId);
  });

  test('the generator reproduces the published file byte for byte', () async {
    final rebuilt = jsonDecode(jsonEncode(await buildFormatVectors()));
    expect(rebuilt, v);
  });
}
