@Tags(['vectors'])
library;

import 'dart:typed_data';

import 'package:quantum_crypto/src/algorithms/algorithms.dart';
import 'package:quantum_crypto/src/encoding/text_encoding.dart';
import 'package:quantum_crypto/src/providers/default_backend.dart';
import 'package:quantum_crypto/src/providers/primitives.dart';
import 'package:test/test.dart';

import '../support/vectors.dart';

void main() {
  // Every symmetric provider shipped by the package must pass the same
  // vectors.
  group('standard backend', () => _symmetric(standardCryptoBackend.symmetric));
  group(
    'PointyCastle backend',
    () => _symmetric(pointyCastleCryptoBackend.symmetric),
  );
  _others();
}

void _symmetric(SymmetricProvider sym) {
  group('AES-256-GCM (Wycheproof)', () {
    final aead = sym.aead(AeadAlgorithm.aes256Gcm);
    var count = 0;
    for (final (_, t) in wycheproofTests('wycheproof_aes_gcm_test.json')) {
      count++;
      test('tcId ${t['tcId']} (${t['result']})', () {
        final key = hex(t['key']);
        final iv = hex(t['iv']);
        final aad = hex(t['aad']);
        final msg = hex(t['msg']);
        final expected = Uint8List.fromList([
          ...hex(t['ct']),
          ...hex(t['tag']),
        ]);
        final opened = aead.open(key, iv, expected, aad);
        if (t['result'] == 'invalid') {
          expect(opened, isNull);
        } else {
          expect(aead.seal(key, iv, msg, aad), expected);
          expect(opened, msg);
        }
      });
    }
    test('vector file is not empty', () => expect(count, greaterThan(40)));
  });

  group('ChaCha20-Poly1305 (Wycheproof)', () {
    final aead = sym.aead(AeadAlgorithm.chacha20Poly1305);
    for (final (g, t) in wycheproofTests(
      'wycheproof_chacha20_poly1305_test.json',
    )) {
      if (g['ivSize'] != 96 || g['keySize'] != 256 || g['tagSize'] != 128) {
        continue;
      }
      test('tcId ${t['tcId']} (${t['result']})', () {
        final key = hex(t['key']);
        final iv = hex(t['iv']);
        final aad = hex(t['aad']);
        final msg = hex(t['msg']);
        final expected = Uint8List.fromList([
          ...hex(t['ct']),
          ...hex(t['tag']),
        ]);
        final opened = aead.open(key, iv, expected, aad);
        if (t['result'] == 'invalid') {
          expect(opened, isNull);
        } else {
          expect(aead.seal(key, iv, msg, aad), expected);
          expect(opened, msg);
        }
      });
    }
  });

  for (final (alg, file) in [
    (KdfAlgorithm.hkdfSha384, 'wycheproof_hkdf_sha384_test.json'),
    (KdfAlgorithm.hkdfSha256, 'wycheproof_hkdf_sha256_test.json'),
  ]) {
    group('${alg.standardName} (Wycheproof)', () {
      final kdf = sym.kdf(alg);
      for (final (_, t) in wycheproofTests(file)) {
        test('tcId ${t['tcId']} (${t['result']})', () {
          final size = t['size'] as int;
          Uint8List derive() => kdf.expand(
            kdf.extract(hex(t['salt']), hex(t['ikm'])),
            hex(t['info']),
            size,
          );
          if (t['result'] == 'invalid') {
            expect(derive, throwsA(anything));
          } else {
            expect(derive(), hex(t['okm']));
          }
        });
      }
    });
  }

  for (final (alg, file) in [
    (HashAlgorithm.sha384, 'wycheproof_hmac_sha384_test.json'),
    (HashAlgorithm.sha256, 'wycheproof_hmac_sha256_test.json'),
  ]) {
    group('HMAC-${alg.standardName} (Wycheproof)', () {
      final mac = sym.hmac(alg);
      for (final (g, t) in wycheproofTests(file)) {
        test('tcId ${t['tcId']} (${t['result']})', () {
          final tagSize = (g['tagSize'] as int) ~/ 8;
          final full = mac.compute(hex(t['key']), hex(t['msg']));
          final tag = full.sublist(0, tagSize);
          if (t['result'] == 'invalid') {
            expect(tag, isNot(hex(t['tag'])));
          } else {
            expect(tag, hex(t['tag']));
          }
        });
      }
    });
  }

  group('SHA-2 (FIPS 180-4 examples)', () {
    final abc = Uint8List.fromList('abc'.codeUnits);
    test('SHA-256("abc")', () {
      expect(
        TextEncoding.toHex(sym.hash(HashAlgorithm.sha256).hash(abc)),
        'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad',
      );
    });
    test('SHA-384("abc")', () {
      expect(
        TextEncoding.toHex(sym.hash(HashAlgorithm.sha384).hash(abc)),
        'cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed'
        '8086072ba1e7cc2358baeca134c825a7',
      );
    });
    test('incremental SHA-384 equals one-shot', () {
      final h = sym.hash(HashAlgorithm.sha384);
      final data = Uint8List.fromList(List.generate(1000, (i) => i & 0xff));
      final sink = h.start()
        ..add(data.sublist(0, 7))
        ..add(data.sublist(7, 600))
        ..add(data.sublist(600));
      expect(sink.close(), h.hash(data));
    });
  });
}

void _others() {
  // Argon2id is PointyCastle's in both shipped backends.
  final sym = standardCryptoBackend.symmetric;

  group('SHA-3 / SHAKE (FIPS 202 examples)', () {
    final k = standardCryptoBackend.keccak;
    test('SHA3-256("abc")', () {
      expect(
        TextEncoding.toHex(k.sha3_256('abc'.codeUnits)),
        '3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532',
      );
    });
    test('SHAKE256("", 32)', () {
      expect(
        TextEncoding.toHex(k.shake256(const [], 32)),
        '46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762f',
      );
    });
  });

  group('Argon2id (RFC 9106 §5.3)', () {
    test('test vector', () {
      final out = sym.argon2id.derive(
        password: Uint8List(32)..fillRange(0, 32, 0x01),
        salt: Uint8List(16)..fillRange(0, 16, 0x02),
        secret: Uint8List(8)..fillRange(0, 8, 0x03),
        associatedData: Uint8List(12)..fillRange(0, 12, 0x04),
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

  group('X25519', () {
    final x = standardCryptoBackend.x25519;
    test('RFC 7748 §5.2 vector 1', () {
      expect(
        TextEncoding.toHex(
          x.sharedSecret(
            hex(
              'a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4',
            ),
            hex(
              'e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c',
            ),
          ),
        ),
        'c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552',
      );
    });
    test('RFC 7748 §6.1 Alice public key', () {
      expect(
        TextEncoding.toHex(
          x.publicKey(
            hex(
              '77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a',
            ),
          ),
        ),
        '8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a',
      );
    });
    for (final (_, t) in wycheproofTests('wycheproof_x25519_test.json')) {
      test('Wycheproof tcId ${t['tcId']} (${t['result']})', () {
        final shared = x.sharedSecret(hex(t['private']), hex(t['public']));
        // "acceptable" cases (low-order points, non-canonical encodings) have
        // a defined RFC 7748 output; X-Wing does not reject them.
        if (t['result'] != 'invalid') {
          expect(TextEncoding.toHex(shared), t['shared']);
        }
      });
    }
  });
}
