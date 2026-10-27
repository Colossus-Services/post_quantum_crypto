import 'dart:io';
import 'dart:typed_data';

import 'package:post_quantum_crypto/post_quantum_crypto.dart';
import 'package:test/test.dart';

import '../support/test_engine.dart';

void main() {
  test('facade round trip', () {
    final enc = PostQuantumCrypto.generateEncryptionKeyPair();
    final env = PostQuantumCrypto.encrypt(
      bytesOf('hello'),
      recipients: [enc.publicKey],
    );
    expect(
      PostQuantumCrypto.decrypt(env, privateKey: enc.privateKey),
      bytesOf('hello'),
    );
    final sig = PostQuantumCrypto.generateSigningKeyPair();
    final s = PostQuantumCrypto.sign(
      bytesOf('hello'),
      privateKey: sig.privateKey,
    );
    expect(
      PostQuantumCrypto.verify(
        bytesOf('hello'),
        signature: s,
        publicKey: sig.publicKey,
      ),
      isTrue,
    );
  });

  test('runInBackground runs in another isolate on the VM', () async {
    expect(backgroundIsolatesSupported, isTrue);
    final kp = await runInBackground(engine.generateSigningKeyPair);
    final sig = engine.sign(bytesOf('m'), privateKey: kp.privateKey);
    expect(
      engine.verify(bytesOf('m'), signature: sig, publicKey: kp.publicKey),
      isTrue,
    );
  });

  test('deterministic engine is reproducible; production is not', () {
    final a = deterministicEngine(5).generateEncryptionKeyPair();
    final b = deterministicEngine(5).generateEncryptionKeyPair();
    expect(a.keyId, b.keyId);
    final c = engine.generateEncryptionKeyPair();
    final d = engine.generateEncryptionKeyPair();
    expect(c.keyId, isNot(d.keyId));
  });

  test('system random returns distinct, correctly sized output', () {
    final r = SystemSecureRandom.instance;
    expect(r.nextBytes(0), isEmpty);
    expect(r.nextBytes(33), hasLength(33));
    expect(r.nextBytes(32), isNot(r.nextBytes(32)));
  });

  group('text encodings', () {
    test('hex', () {
      expect(TextEncoding.toHex([0, 1, 254, 255]), '0001feff');
      expect(TextEncoding.fromHex('0001FEff'), [0, 1, 254, 255]);
      expect(
        () => TextEncoding.fromHex('abc'),
        throwsA(isA<MalformedDataException>()),
      );
      expect(
        () => TextEncoding.fromHex('zz'),
        throwsA(isA<MalformedDataException>()),
      );
    });

    test('base64url', () {
      final b = Uint8List.fromList([251, 255, 0]);
      expect(TextEncoding.toBase64Url(b), '-_8A');
      expect(TextEncoding.fromBase64Url('-_8A'), b);
      expect(
        () => TextEncoding.fromBase64Url('+/8A'),
        throwsA(isA<MalformedDataException>()),
      );
    });

    test('envelopes survive textual transport', () {
      final kp = engine.generateEncryptionKeyPair();
      final env = engine.encrypt(bytesOf('m'), recipients: [kp.publicKey]);
      final text = TextEncoding.toBase64Url(env.toBytes());
      expect(
        engine.decryptBytes(
          TextEncoding.fromBase64Url(text),
          privateKey: kp.privateKey,
        ),
        bytesOf('m'),
      );
    });
  });

  test('error messages carry no key material', () {
    final kp = engine.generateEncryptionKeyPair();
    final env = engine.encrypt(bytesOf('m'), recipients: [kp.publicKey]);
    final bytes = env.toBytes();
    try {
      engine.decryptBytes(
        flip(bytes, bytes.length - 1),
        privateKey: kp.privateKey,
      );
      fail('should throw');
    } on DecryptionFailedException catch (e) {
      expect(
        e.toString(),
        'DecryptionFailedException: Authenticated decryption failed',
      );
    }
  });

  test('version matches pubspec', () {
    final pubspec = File('pubspec.yaml').readAsStringSync();
    final version = RegExp(
      r'^version:\s*(\S+)',
      multiLine: true,
    ).firstMatch(pubspec)!.group(1);
    expect(postQuantumCryptoVersion, version);
  }, tags: ['version']);
}
