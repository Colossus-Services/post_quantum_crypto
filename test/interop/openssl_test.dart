/// Cross-implementation tests against OpenSSL ≥ 3.5 (ML-KEM, ML-DSA and
/// SLH-DSA support). Set `OPENSSL` to the binary to use; the tests skip
/// themselves when no suitable OpenSSL is found.
@Tags(['interop'])
library;

import 'dart:io';
import 'dart:typed_data';

import 'package:post_quantum_crypto/post_quantum_crypto.dart';
import 'package:test/test.dart';

import '../support/test_engine.dart';

String? _findOpenssl() {
  final candidates = [
    ?Platform.environment['OPENSSL'],
    '/opt/homebrew/bin/openssl',
    '/usr/local/opt/openssl@3/bin/openssl',
    '/usr/local/bin/openssl',
    'openssl',
  ];
  for (final c in candidates) {
    try {
      final r = Process.runSync(c, ['list', '-kem-algorithms']);
      if (r.exitCode == 0 && '${r.stdout}'.contains('ML-KEM-768')) return c;
    } on ProcessException {
      continue;
    }
  }
  return null;
}

void main() {
  final openssl = _findOpenssl();
  // CI sets QC_REQUIRE_OPENSSL so a missing OpenSSL fails instead of skipping.
  if (openssl == null && Platform.environment['QC_REQUIRE_OPENSSL'] == 'true') {
    test('OpenSSL >= 3.5 is available', () => fail('OpenSSL not found'));
    return;
  }
  final skip = openssl == null ? 'OpenSSL with ML-KEM not found' : null;
  late Directory dir;

  setUp(() => dir = Directory.systemTemp.createTempSync('qc_ossl_'));
  tearDown(() => dir.deleteSync(recursive: true));

  String f(String name) => '${dir.path}/$name';

  void run(List<String> args) {
    final r = Process.runSync(openssl!, args);
    if (r.exitCode != 0) {
      fail('openssl ${args.join(' ')} failed:\n${r.stderr}');
    }
  }

  group('ML-KEM-768', () {
    test('OpenSSL key → we decapsulate OpenSSL encapsulation', () {
      run(['genpkey', '-algorithm', 'ML-KEM-768', '-out', f('k.pem')]);
      run(['pkey', '-in', f('k.pem'), '-pubout', '-out', f('pub.pem')]);
      run([
        'pkeyutl',
        '-encap',
        '-pubin',
        '-inkey',
        f('pub.pem'),
        '-out',
        f('ct.bin'),
        '-secret',
        f('ss.bin'),
      ]);
      final priv =
          engine.importPrivateKeyPem(File(f('k.pem')).readAsStringSync())
              as EncryptionPrivateKey;
      final pub = engine.importPublicKeyPem(
        File(f('pub.pem')).readAsStringSync(),
      );
      expect(pub, priv.publicKey);
      final ss = engine.ctx
          .kem(KemAlgorithm.mlKem768)
          .decapsulate(priv.secret, File(f('ct.bin')).readAsBytesSync());
      expect(ss, File(f('ss.bin')).readAsBytesSync());
    });

    test('our key → OpenSSL decapsulates our encapsulation', () {
      final kp = engine.generateEncryptionKeyPair();
      for (final form in PrivateKeyDerForm.values) {
        File(f('k.pem')).writeAsStringSync(
          engine.exportPrivateKeyPem(kp.privateKey, form: form),
        );
        final enc = engine.ctx
            .kem(KemAlgorithm.mlKem768)
            .encapsulate(kp.publicKey.bytes, engine.ctx.randomBytes(32));
        File(f('ct.bin')).writeAsBytesSync(enc.ciphertext);
        run([
          'pkeyutl',
          '-decap',
          '-inkey',
          f('k.pem'),
          '-in',
          f('ct.bin'),
          '-out',
          f('ss.bin'),
        ]);
        expect(
          File(f('ss.bin')).readAsBytesSync(),
          enc.sharedSecret,
          reason: form.name,
        );
      }
      // OpenSSL derives the same public key from our private key.
      File(
        f('k.pem'),
      ).writeAsStringSync(engine.exportPrivateKeyPem(kp.privateKey));
      run([
        'pkey',
        '-in',
        f('k.pem'),
        '-pubout',
        '-outform',
        'DER',
        '-out',
        f('p.der'),
      ]);
      expect(
        File(f('p.der')).readAsBytesSync(),
        engine.exportPublicKeyDer(kp.publicKey),
      );
    });
  }, skip: skip);

  group('ML-DSA-65', () {
    test('OpenSSL signs → we verify; we sign → OpenSSL verifies', () {
      final msg = Uint8List.fromList(List.generate(300, (i) => i));
      File(f('msg.bin')).writeAsBytesSync(msg);
      run(['genpkey', '-algorithm', 'ML-DSA-65', '-out', f('k.pem')]);
      run(['pkey', '-in', f('k.pem'), '-pubout', '-out', f('pub.pem')]);
      run([
        'pkeyutl',
        '-sign',
        '-rawin',
        '-inkey',
        f('k.pem'),
        '-in',
        f('msg.bin'),
        '-out',
        f('sig.bin'),
        '-pkeyopt',
        'hexcontext-string:01020304',
      ]);
      final priv =
          engine.importPrivateKeyPem(File(f('k.pem')).readAsStringSync())
              as SigningPrivateKey;
      final pub =
          engine.importPublicKeyPem(File(f('pub.pem')).readAsStringSync())
              as SigningPublicKey;
      expect(pub, priv.publicKey);
      expect(
        engine.verify(
          msg,
          signature: File(f('sig.bin')).readAsBytesSync(),
          publicKey: pub,
          context: [1, 2, 3, 4],
        ),
        isTrue,
      );

      final ours = engine.sign(msg, privateKey: priv, context: [9, 9]);
      File(f('sig2.bin')).writeAsBytesSync(ours);
      run([
        'pkeyutl',
        '-verify',
        '-rawin',
        '-pubin',
        '-inkey',
        f('pub.pem'),
        '-in',
        f('msg.bin'),
        '-sigfile',
        f('sig2.bin'),
        '-pkeyopt',
        'hexcontext-string:0909',
      ]);
    });

    test('our PKCS#8 seed key is accepted by OpenSSL', () {
      final kp = engine.generateSigningKeyPair();
      File(
        f('k.pem'),
      ).writeAsStringSync(engine.exportPrivateKeyPem(kp.privateKey));
      run([
        'pkey',
        '-in',
        f('k.pem'),
        '-pubout',
        '-outform',
        'DER',
        '-out',
        f('p.der'),
      ]);
      expect(
        File(f('p.der')).readAsBytesSync(),
        engine.exportPublicKeyDer(kp.publicKey),
      );
    });
  }, skip: skip);

  group('SLH-DSA-SHAKE-128f', () {
    test('cross verification', () {
      final msg = Uint8List.fromList('slh-dsa interop'.codeUnits);
      File(f('msg.bin')).writeAsBytesSync(msg);
      run(['genpkey', '-algorithm', 'SLH-DSA-SHAKE-128f', '-out', f('k.pem')]);
      run(['pkey', '-in', f('k.pem'), '-pubout', '-out', f('pub.pem')]);
      run([
        'pkeyutl',
        '-sign',
        '-rawin',
        '-inkey',
        f('k.pem'),
        '-in',
        f('msg.bin'),
        '-out',
        f('sig.bin'),
      ]);
      final priv =
          engine.importPrivateKeyPem(File(f('k.pem')).readAsStringSync())
              as SigningPrivateKey;
      final pub =
          engine.importPublicKeyPem(File(f('pub.pem')).readAsStringSync())
              as SigningPublicKey;
      expect(priv.publicKey, pub);
      expect(
        engine.verify(
          msg,
          signature: File(f('sig.bin')).readAsBytesSync(),
          publicKey: pub,
        ),
        isTrue,
      );
      File(f('sig2.bin')).writeAsBytesSync(engine.sign(msg, privateKey: priv));
      run([
        'pkeyutl',
        '-verify',
        '-rawin',
        '-pubin',
        '-inkey',
        f('pub.pem'),
        '-in',
        f('msg.bin'),
        '-sigfile',
        f('sig2.bin'),
      ]);
      // Our PKCS#8 export round-trips through OpenSSL.
      File(f('ours.pem')).writeAsStringSync(engine.exportPrivateKeyPem(priv));
      run([
        'pkey',
        '-in',
        f('ours.pem'),
        '-pubout',
        '-outform',
        'DER',
        '-out',
        f('p.der'),
      ]);
      expect(
        File(f('p.der')).readAsBytesSync(),
        engine.exportPublicKeyDer(pub),
      );
    });
  }, skip: skip);
}
