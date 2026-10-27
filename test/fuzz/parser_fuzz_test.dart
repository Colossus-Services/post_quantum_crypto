/// Seeded mutation fuzzing of every public parser and decoder.
///
/// Property: for any input, a parser either succeeds or throws a
/// [PostQuantumCryptoException]; it never throws `RangeError`, `StateError`,
/// `TypeError`, `ArgumentError` or similar, and never hangs. Set
/// `QC_FUZZ_ITERATIONS` to run longer (default 300 per target).
@Tags(['fuzz'])
library;

import 'dart:io';
import 'dart:math';
import 'dart:typed_data';

import 'package:post_quantum_crypto/post_quantum_crypto.dart';
import 'package:test/test.dart';

import '../support/test_engine.dart';
import '../unit/key_serialization_test.dart' show fastArgon;

final int _iterations =
    int.tryParse(Platform.environment['QC_FUZZ_ITERATIONS'] ?? '') ?? 300;

/// Not cryptographic: a seeded generator for reproducible mutations.
Uint8List _mutate(Random rnd, Uint8List input) {
  final b = input.toList();
  final ops = 1 + rnd.nextInt(4);
  for (var k = 0; k < ops; k++) {
    if (b.isEmpty) {
      b.add(rnd.nextInt(256));
      continue;
    }
    switch (rnd.nextInt(7)) {
      case 0: // bit flip
        b[rnd.nextInt(b.length)] ^= 1 << rnd.nextInt(8);
      case 1: // random byte
        b[rnd.nextInt(b.length)] = rnd.nextInt(256);
      case 2: // truncate
        b.length = rnd.nextInt(b.length);
      case 3: // insert
        b.insert(rnd.nextInt(b.length + 1), rnd.nextInt(256));
      case 4: // delete
        b.removeAt(rnd.nextInt(b.length));
      case 5: // max out a would-be length field
        final i = rnd.nextInt(b.length);
        for (var j = i; j < i + 4 && j < b.length; j++) {
          b[j] = 0xff;
        }
      case 6: // duplicate a slice
        final s = rnd.nextInt(b.length);
        final e = min(b.length, s + 1 + rnd.nextInt(64));
        b.insertAll(e, b.sublist(s, e));
    }
  }
  return Uint8List.fromList(b);
}

void _fuzz(String name, Uint8List seed, void Function(Uint8List) parse) {
  test(name, () {
    final rnd = Random(name.hashCode);
    parse(seed); // the unmutated input must be accepted
    for (var i = 0; i < _iterations; i++) {
      final input = i % 50 == 49
          ? Uint8List.fromList(
              List.generate(rnd.nextInt(2048), (_) => rnd.nextInt(256)),
            )
          : _mutate(rnd, seed);
      try {
        parse(input);
      } on PostQuantumCryptoException {
        // expected
      } catch (e, st) {
        fail('iteration $i: unexpected ${e.runtimeType}: $e\n$st');
      }
    }
  });
}

void main() {
  final enc = engine.generateEncryptionKeyPair();
  final hyb = engine.generateEncryptionKeyPair(algorithm: KemAlgorithm.xWing);
  final sig = engine.generateSigningKeyPair();
  final envelope = engine
      .encrypt(
        bytesOf('fuzz me'),
        recipients: [enc.publicKey, hyb.publicKey],
        context: {'a': 'b'},
      )
      .toBytes();

  _fuzz('envelope parse', envelope, engine.parseEnvelope);
  _fuzz(
    'envelope decrypt',
    envelope,
    (b) => engine.decryptBytes(b, privateKey: enc.privateKey),
  );
  _fuzz(
    'key record (public)',
    engine.encodeKey(enc.publicKey),
    engine.decodeKey,
  );
  _fuzz(
    'key record (private)',
    engine.encodeKey(sig.privateKey),
    engine.decodeKey,
  );
  _fuzz(
    'SPKI DER',
    engine.exportPublicKeyDer(sig.publicKey),
    engine.importPublicKeyDer,
  );
  _fuzz(
    'PKCS#8 DER',
    engine.exportPrivateKeyDer(enc.privateKey, form: PrivateKeyDerForm.both),
    engine.importPrivateKeyDer,
  );
  final content = bytesOf('signed');
  _fuzz(
    'detached signature',
    engine.signDetached(content, privateKey: sig.privateKey).toBytes(),
    (b) => engine.verifyDetached(
      content,
      signature: engine.parseDetachedSignature(b),
      publicKey: sig.publicKey,
    ),
  );
  _fuzz(
    'signed artifact',
    engine.createSignedArtifact(content, privateKey: sig.privateKey).toBytes(),
    (b) => engine.openSignedArtifact(b, publicKey: sig.publicKey),
  );
  _fuzz(
    'signed manifest',
    engine.createSignedManifest([
      engine.manifestEntry('a/b.txt', content),
      engine.manifestEntry('c', content),
    ], privateKey: sig.privateKey).toBytes(),
    (b) => engine.verifyManifest(
      engine.parseSignedManifest(b),
      publicKey: sig.publicKey,
    ),
  );
  const t = HybridTranscript(protocol: 'p', initiatorId: 'i', responderId: 'r');
  _fuzz(
    'hybrid message',
    engine.establishHybridKey(hyb.publicKey, transcript: t).message,
    (b) => engine.acceptHybridKey(b, privateKey: hyb.privateKey, transcript: t),
  );
  // Password objects: a policy whose Argon2id ceiling equals the floor keeps
  // every accepted mutation cheap.
  final cheap = engine.withPolicy(
    const SecurityPolicy(
      password: PasswordPolicy(maxMemoryKiB: 8 * 1024, maxIterations: 1),
    ),
  );
  _fuzz(
    'password-protected data',
    cheap.encryptWithPassword(content, 'pw', parameters: fastArgon),
    (b) => cheap.decryptWithPassword(b, 'pw'),
  );
  _fuzz('hex / base64url decoders', Uint8List.fromList('00ff-_AA'.codeUnits), (
    b,
  ) {
    final s = String.fromCharCodes(b);
    try {
      TextEncoding.fromHex(s);
    } on MalformedDataException {
      // expected
    }
    TextEncoding.fromBase64Url(s);
  });

  test('stream decrypt', () async {
    final rnd = Random(7);
    final ct =
        (await engine
                .encryptStream(
                  Stream.value(Uint8List(3000)),
                  recipients: [enc.publicKey],
                  chunkSize: 1024,
                )
                .toList())
            .expand((e) => e)
            .toList();
    for (var i = 0; i < _iterations ~/ 3; i++) {
      final input = _mutate(rnd, Uint8List.fromList(ct));
      try {
        await engine
            .decryptStream(Stream.value(input), privateKey: enc.privateKey)
            .drain<void>();
      } on PostQuantumCryptoException {
        // expected
      } catch (e, st) {
        fail('iteration $i: unexpected ${e.runtimeType}: $e\n$st');
      }
    }
  });
}
