/// Builds the published format test vectors for quantum_crypto v1.
///
/// Every object is produced by a deterministic engine, so the output is
/// reproducible; `format_vectors_test.dart` checks both that the stored
/// objects decrypt/verify and that this function still reproduces them byte
/// for byte (format stability).
///
/// Regenerate with: dart run test/vectors/generate_format_vectors.dart
library;

import 'dart:convert';
import 'dart:typed_data';

import 'package:quantum_crypto/quantum_crypto.dart';

import '../support/test_engine.dart';

String _hex(List<int> b) => TextEncoding.toHex(b);

const _argon = Argon2idParameters(
  memoryKiB: 8 * 1024,
  iterations: 1,
  parallelism: 1,
);

const formatTranscript = HybridTranscript(
  protocol: 'quantum_crypto/test-vectors',
  initiatorId: 'alice',
  responderId: 'bob',
  extra: {'session': '1'},
);

/// Returns the vector set as a JSON-serializable map.
Future<Map<String, Object>> buildFormatVectors() async {
  final e = deterministicEngine(2026);
  final created = KeyMetadata(createdAt: DateTime.utc(2026, 1, 1));
  final mlkem = e.generateEncryptionKeyPair(metadata: created);
  final xwing = e.generateEncryptionKeyPair(
    algorithm: KemAlgorithm.xWing,
    metadata: created,
  );
  final mldsa = e.generateSigningKeyPair(metadata: created);

  final plaintext = utf8.encode('quantum_crypto format test vector');
  final context = {'purpose': 'test-vector', 'tenant': 'example'};

  final envelope = e.encrypt(
    plaintext,
    recipients: [mlkem.publicKey, xwing.publicKey],
    context: context,
  );
  final chacha = e.encrypt(
    plaintext,
    recipients: [mlkem.publicKey],
    aead: AeadAlgorithm.chacha20Poly1305,
  );
  final streamPlain = Uint8List.fromList(List.generate(600, (i) => i & 0xff));
  final stream = await e
      .encryptStream(
        Stream.value(streamPlain),
        recipients: [mlkem.publicKey],
        chunkSize: 256,
        context: context,
      )
      .expand((c) => c)
      .toList();
  final detached = e.signDetached(
    plaintext,
    privateKey: mldsa.privateKey,
    context: utf8.encode('test-vectors'),
    metadata: {'name': 'message.txt'},
  );
  final rawSignature = e.sign(
    plaintext,
    privateKey: mldsa.privateKey,
    context: utf8.encode('test-vectors'),
  );
  final manifest = e.createSignedManifest([
    e.manifestEntry('a.txt', utf8.encode('a')),
    e.manifestEntry('dir/b.bin', Uint8List(3)),
  ], privateKey: mldsa.privateKey);
  final hybrid = e.establishHybridKey(
    xwing.publicKey,
    transcript: formatTranscript,
  );
  final protectedKey = e.exportPrivateKeyWithPassword(
    mldsa.privateKey,
    'test-vector password',
    parameters: _argon,
  );

  return {
    'description':
        'quantum_crypto format v1 test vectors. Keys are given as seeds; '
        'all objects are canonical binary encodings in hex. See '
        'doc/FORMATS.md.',
    'version': 1,
    'keys': {
      'mlKem768': {
        'seed': _hex(mlkem.privateKey.seed),
        'publicKey': _hex(mlkem.publicKey.bytes),
        'keyId': mlkem.keyId.hex,
      },
      'xWing': {
        'seed': _hex(xwing.privateKey.seed),
        'publicKey': _hex(xwing.publicKey.bytes),
        'keyId': xwing.keyId.hex,
      },
      'mlDsa65': {
        'seed': _hex(mldsa.privateKey.seedOrNull!),
        'publicKey': _hex(mldsa.publicKey.bytes),
        'keyId': mldsa.keyId.hex,
      },
    },
    'plaintext': _hex(plaintext),
    'context': context,
    'envelope': _hex(envelope.toBytes()),
    'envelopeChaCha20Poly1305': _hex(chacha.toBytes()),
    'streamPlaintext': _hex(streamPlain),
    'stream': _hex(stream),
    'signatureContext': _hex(utf8.encode('test-vectors')),
    'rawSignature': _hex(rawSignature),
    'detachedSignature': _hex(detached.toBytes()),
    'manifest': _hex(manifest.toBytes()),
    'hybrid': {
      'message': _hex(hybrid.message),
      'sessionKey': _hex(hybrid.sessionKey),
    },
    'keyRecordPublic': _hex(e.encodeKey(mlkem.publicKey)),
    'passwordProtectedKey': {
      'password': 'test-vector password',
      'blob': _hex(protectedKey),
    },
  };
}
