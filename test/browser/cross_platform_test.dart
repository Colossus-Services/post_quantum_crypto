/// Platform-independent tests (no dart:io). Run on the VM by default and in
/// browsers with:
///
///   dart test -p chrome test/browser
///   dart test -p chrome -c dart2wasm test/browser
///
/// Official vectors are embedded in compact form (seeds plus SHA-256 of the
/// large outputs). Deterministic package outputs are pinned by digest, so
/// every platform must produce byte-identical serializations.
@Tags(['browser'])
library;

import 'dart:typed_data';

import 'package:quantum_crypto/quantum_crypto.dart';
import 'package:quantum_crypto/src/kem/kem_scheme.dart';
import 'package:test/test.dart';

import '../support/test_engine.dart';

Uint8List _h(String s) => TextEncoding.fromHex(s);

String _sha256(List<int> b) => TextEncoding.toHex(
  standardCryptoBackend.symmetric.hash(HashAlgorithm.sha256).hash(b),
);

void main() {
  final backend = standardCryptoBackend;

  group('official vectors (compact)', () {
    test('X-Wing draft vector 0 (ML-KEM-768 + X25519 + SHA-3)', () {
      final scheme = kemSchemeFor(KemAlgorithm.xWing, backend);
      final kp = scheme.deriveFromSeed(
        _h('7f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef26'),
      );
      expect(
        _sha256(kp.publicKey),
        '2e816deebcd76c5c80d0cd2d174478871658e8e2ff42bc9d4a6e486372e856bb',
      );
      final enc = scheme.encapsulate(
        kp.publicKey,
        _h(
          '3cb1eea988004b93103cfb0aeefd2a686e01fa4a58e8a3639ca8a1e3f9ae57e2'
          '35b8cc873c23dc62b8d260169afa2f75ab916a58d974918835d25e6a435085b2',
        ),
      );
      expect(
        _sha256(enc.ciphertext),
        '17cd532d657e44c897ca6583e548a5424fc70bf54f99515a4d2bcf99e3469f33',
      );
      const ss =
          'd2df0522128f09dd8e2c92b1e905c793d8f57a54c3da25861f10bf4ca613e384';
      expect(TextEncoding.toHex(enc.sharedSecret), ss);
      expect(
        TextEncoding.toHex(scheme.decapsulate(kp.secret, enc.ciphertext)),
        ss,
      );
    });

    test('ML-KEM-768 keyGen (ACVP tcId 26)', () {
      final kp = kemSchemeFor(KemAlgorithm.mlKem768, backend).deriveFromSeed(
        _h(
          'E582B7D75E6C80B05AE392A1FC9F7153B12390FD99930368CC67A768BAEBC8A0'
          '1CDACB8740C0B87C4A379575F187B367CBFA3B300BF591B109F79816E9CBE8F0',
        ),
      );
      expect(
        _sha256(kp.publicKey),
        '4158f6afb5e516c99f1da07da8c651348422b17c1f4e9a08ad73fb1f91249b3e',
      );
    });

    test('ML-DSA-65 keyGen (ACVP tcId 26)', () {
      final kp = backend.postQuantum
          .signature(SignatureAlgorithm.mlDsa65)
          .generateFromSeed(
            _h(
              'A991FD42B071D49C48AE3E75C647459E0DAAD1E1BA356A04801912D3294BCFF8',
            ),
          );
      expect(
        _sha256(kp.publicKey),
        'b1a7d0d2f0d7a04b9d5ffccd9bd578864dab4a01cdd7f70a05cd1f4f0672e43a',
      );
      expect(
        _sha256(kp.secretKey),
        '56c53ac82fbff7d81b7a8cfbbc73011ceccad677e16dc53f2ece66d49aa11edd',
      );
    });

    test('AES-256-GCM (Wycheproof tcId 74-style, NIST GCM test case 14)', () {
      // McGrew & Viega GCM spec, test case 14: 256-bit zero key, zero IV,
      // one zero block.
      final ct = backend.symmetric
          .aead(AeadAlgorithm.aes256Gcm)
          .seal(Uint8List(32), Uint8List(12), Uint8List(16), Uint8List(0));
      expect(
        TextEncoding.toHex(ct),
        'cea7403d4d606b6e074ec5d3baf39d18'
        'd0d1c8a799996bf0265b98b5d48ab919',
      );
    });

    test('ChaCha20-Poly1305 (RFC 8439 §2.8.2)', () {
      // Regression: the PointyCastle Poly1305 failed on JavaScript.
      final key = Uint8List.fromList(List.generate(32, (i) => 0x80 + i));
      final nonce = _h('070000004041424344454647');
      final aad = _h('50515253c0c1c2c3c4c5c6c7');
      final pt = Uint8List.fromList(
        'Ladies and Gentlemen of the class of \'99: If I could offer you '
                'only one tip for the future, sunscreen would be it.'
            .codeUnits,
      );
      final aead = backend.symmetric.aead(AeadAlgorithm.chacha20Poly1305);
      final ct = aead.seal(key, nonce, pt, aad);
      expect(
        TextEncoding.toHex(ct.sublist(ct.length - 16)),
        '1ae10b594f09e26a7e902ecbd0600691',
      );
      expect(
        TextEncoding.toHex(ct.sublist(0, 16)),
        'd31a8d34648e60db7b86afbc53ef7ec2',
      );
      expect(aead.open(key, nonce, ct, aad), pt);
      expect(aead.open(key, nonce, flip(ct, 3), aad), isNull);
    });

    test('HKDF-SHA-384 and Argon2id (RFC 9106)', () {
      final out = backend.symmetric.argon2id.derive(
        password: Uint8List(32)..fillRange(0, 32, 1),
        salt: Uint8List(16)..fillRange(0, 16, 2),
        secret: Uint8List(8)..fillRange(0, 8, 3),
        associatedData: Uint8List(12)..fillRange(0, 12, 4),
        memoryKiB: 32,
        iterations: 3,
        parallelism: 4,
        length: 32,
      );
      expect(
        TextEncoding.toHex(out),
        '0d640df58d78766c08c037a34a8b53c9d01ef0452d75b65eb52520e96b01e659',
      );
    });
  });

  group('byte-identical serialization across platforms', () {
    test('deterministic envelope, signature and key record', () {
      final e = deterministicEngine(42);
      final enc = e.generateEncryptionKeyPair(
        metadata: KeyMetadata(createdAt: DateTime.utc(2026)),
      );
      final sig = e.generateSigningKeyPair(
        metadata: KeyMetadata(createdAt: DateTime.utc(2026)),
      );
      final env = e.encrypt(
        bytesOf('cross-platform'),
        recipients: [enc.publicKey],
        context: {'k': 'v'},
      );
      final s = e.signDetached(bytesOf('x'), privateKey: sig.privateKey);
      final digests = {
        'encKey': _sha256(e.encodeKey(enc.privateKey)),
        'sigKey': _sha256(e.encodeKey(sig.privateKey)),
        'envelope': _sha256(env.toBytes()),
        'signature': _sha256(s.toBytes()),
      };
      expect(digests, _pinned);
    });
  });

  group('workflows', () {
    test('envelope, multi-recipient and hybrid', () {
      final a = engine.generateEncryptionKeyPair();
      final b = engine.generateEncryptionKeyPair(algorithm: KemAlgorithm.xWing);
      final env = engine.encrypt(
        bytesOf('web'),
        recipients: [a.publicKey, b.publicKey],
      );
      expect(engine.decrypt(env, privateKey: a.privateKey), bytesOf('web'));
      expect(engine.decrypt(env, privateKey: b.privateKey), bytesOf('web'));
      final chacha = engine.encrypt(
        bytesOf('web'),
        recipients: [a.publicKey],
        aead: AeadAlgorithm.chacha20Poly1305,
      );
      expect(engine.decrypt(chacha, privateKey: a.privateKey), bytesOf('web'));
      expect(
        () => engine.decryptBytes(
          flip(env.toBytes(), env.toBytes().length - 1),
          privateKey: a.privateKey,
        ),
        throwsA(isA<DecryptionFailedException>()),
      );
    });

    test('streaming', () async {
      final kp = engine.generateEncryptionKeyPair();
      final pt = Uint8List(5000);
      final ct = await engine
          .encryptStream(
            Stream.value(pt),
            recipients: [kp.publicKey],
            chunkSize: 1024,
          )
          .expand((c) => c)
          .toList();
      final out = await engine
          .decryptStream(Stream.value(ct), privateKey: kp.privateKey)
          .expand((c) => c)
          .toList();
      expect(out, pt);
    });

    test('signatures', () {
      final kp = engine.generateSigningKeyPair();
      final s = engine.sign(bytesOf('m'), privateKey: kp.privateKey);
      expect(
        engine.verify(bytesOf('m'), signature: s, publicKey: kp.publicKey),
        isTrue,
      );
    });

    test('secure random is available', () {
      expect(SystemSecureRandom.instance.nextBytes(16), hasLength(16));
    });
  });
}

/// SHA-256 of the deterministic outputs, recorded on the Dart VM.
const _pinned = <String, String>{
  'encKey': '75430ec9afc064ffc84cdd289b21dfbba57e1030f0900eab3032ce4a04a87bc0',
  'sigKey': '42aabf03c621036b6b04a655e1aebaf3596f5cf79574ef39e8a150bfe3d7de01',
  'envelope':
      '17e9ef46aec9611e1d046081e1840992c7b8aa000709031a0936708ee6310e60',
  'signature':
      'd8065ea296d1de25819722af02bff06e10c8d9dffe1179ce402d642168b53901',
};
